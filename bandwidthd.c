#include "bandwidthd.h"

#ifdef HAVE_LIBPQ
#include <libpq-fe.h>
#endif

// We must call regular exit to write out profile data, but child forks are supposed to usually
// call _exit?
#ifdef PROFILE
#define _exit(x) exit(x)
#endif

/*
#ifdef DEBUG
#define fork() (0)
#endif
*/

// ****************************************************************************************
// ** Global Variables
// ****************************************************************************************

static pcap_t *pd;

unsigned int GraphIntervalCount = 0;
unsigned int IpCount = 0;
unsigned int SubnetCount = 0;
time_t IntervalStart;
time_t ProgramStart;
int RotateLogs = FALSE;
    
struct SubnetData SubnetTable[SUBNET_NUM];
struct IPData IpTable[IP_NUM];

int DataLink;
int IP_Offset;

struct IPDataStore *IPDataStore = NULL;
extern int bdconfig_parse(void);
extern FILE *bdconfig_in;

struct config config;

pid_t workerchildpids[NR_WORKER_CHILDS];

void signal_handler(int sig)
	{
	switch (sig) 
		{
		case SIGHUP:
			signal(SIGHUP, signal_handler);
			RotateLogs++;
			if (config.tag == '1') 
				{
				int i;

				/* signal children */
				for (i=0; i < NR_WORKER_CHILDS; i++) 
					kill(workerchildpids[i], SIGHUP);
				}
			break;
		case SIGTERM:
			if (config.tag == '1') 
				{
				int i;

				/* send term signal to children */
				for (i=0; i < NR_WORKER_CHILDS; i++) 
					kill(workerchildpids[i], SIGTERM);
				}
			// TODO: Might want to make sure we're not in the middle of wrighting out a log file
			exit(0);
			break;
		}
	}

void bd_CollectingData(char *filename)
	{
	FILE *index;

	index = fopen(filename, "wt");	
	if (index)
		{
		fprintf(index, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n");
		fprintf(index, "<HTML><HEAD><TITLE>Bandwidthd</TITLE>\n");

		if (config.meta_refresh)
			fprintf(index, "<META HTTP-EQUIV=\"REFRESH\" content=\"%u\">\n",
					config.meta_refresh);
		fprintf(index, "<META HTTP-EQUIV=\"EXPIRES\" content=\"-1\">\n");
		fprintf(index, "<META HTTP-EQUIV=\"PRAGMA\" content=\"no-cache\">\n");
		fprintf(index, "</HEAD>\n<BODY><center><img src=\"logo.gif\" ALT=\"Logo\"><BR>\n");
		fprintf(index, "<BR>\n - <a href=\"index.html\">Daily</a> -- <a href=\"index2.html\">Weekly</a> -- ");
		fprintf(index, "<a href=\"index3.html\">Monthly</a> -- <a href=\"index4.html\">Yearly</a><BR>\n");
		fprintf(index, "</CENTER><BR>bandwidthd has nothing to graph.  This message should be replaced by graphs in a few minutes.  If it's not, please see the section titled \"Known Bugs and Troubleshooting\" in the README");		
		fprintf(index, "</BODY></HTML>\n");
		fclose(index);
		}
	else
		{
		syslog(LOG_ERR, "Cannot open %s for writing", filename);
		exit(1);
		}
	}

int WriteOutWebpages(long int timestamp)
{
	struct IPDataStore *DataStore = IPDataStore;
	struct SummaryData **SummaryData;
	int NumGraphs = 0;
	pid_t graphpid;
	int Counter;

	/* Did we catch any packets since last time? */
	if (!DataStore) return -1;

	// break off from the main line so we don't miss any packets while we graph
	graphpid = fork();

	switch (graphpid) {
		case 0: /* we're the child, graph. */
			{
#ifdef PROFILE
			// Got this incantation from a message board.  Don't forget to set
			// GMON_OUT_PREFIX in the shell
			extern void _start(void), etext(void);
			syslog(LOG_INFO, "Calling profiler startup...");
			monstartup((u_long) &_start, (u_long) &etext);
#endif
          	signal(SIGHUP, SIG_IGN);
			
    	    nice(4); // reduce priority so I don't choke out other tasks

			// Count Number of IP's in datastore
			for (DataStore = IPDataStore, Counter = 0; DataStore; Counter++, DataStore = DataStore->Next);

			// +1 because we don't want to accidently allocate 0
			SummaryData = malloc(sizeof(struct SummaryData *)*Counter+1);

			DataStore = IPDataStore;
			while (DataStore) // Is not null
				{
				if (DataStore->FirstBlock->NumEntries > 0)
					{
					SummaryData[NumGraphs] = (struct SummaryData *) malloc(sizeof(struct SummaryData));
					GraphIp(DataStore, SummaryData[NumGraphs++], timestamp+LEAD*config.range);
					}
			    DataStore = DataStore->Next;
				}

			MakeIndexPages(NumGraphs, SummaryData);
	
			_exit(0);
			}
		break;

		case -1:
			syslog(LOG_ERR, "Forking grapher child failed!");
			return -2;
		break;

		default: /* parent + successful fork, assume graph success */
			return 0;
		break;
	}
}

void setchildconfig (int level) {
	static unsigned long long graph_cutoff;

	switch (level) {
		case 0:
			config.range = RANGE1;
			config.interval = INTERVAL1;
			config.tag = '1';
			graph_cutoff = config.graph_cutoff;
		break;
		case 1:
			// Overide skip_intervals for children
			config.skip_intervals = CONFIG_GRAPHINTERVALS;
			config.range = RANGE2;
			config.interval = INTERVAL2;
			config.tag = '2';
			config.graph_cutoff = graph_cutoff*(RANGE2/RANGE1);	
		break;
		case 2:
			// Overide skip_intervals for children
			config.skip_intervals = CONFIG_GRAPHINTERVALS;
			config.range = RANGE3;
			config.interval = INTERVAL3;
			config.tag = '3';
			config.graph_cutoff = graph_cutoff*(RANGE3/RANGE1);
		break;
		case 3:
			// Overide skip_intervals for children
			config.skip_intervals = CONFIG_GRAPHINTERVALS;
			config.range = RANGE4;
			config.interval = INTERVAL4;
			config.tag = '4';
			config.graph_cutoff = graph_cutoff*(RANGE4/RANGE1);
		break;

		default:
			syslog(LOG_ERR, "setchildconfig got an invalid level argument: %d", level);
			_exit(1);
	}
}

void makepidfile(pid_t pid) 
	{
	FILE *pidfile;

	pidfile = fopen("/var/run/bandwidthd.pid", "wt");
	if (pidfile) 
		{
		if (fprintf(pidfile, "%d\n", pid) == 0) 
			{
			syslog(LOG_ERR, "Bandwidthd: failed to write '%d' to /var/run/bandwidthd.pid", pid);
			fclose(pidfile);
			unlink("/var/run/bandwidthd.pid");
			}
		else
			fclose(pidfile);		
		}
	else
		syslog(LOG_ERR, "Could not open /var/run/bandwidthd.pid for write");
	}


int main(int argc, char **argv)
    {
    struct bpf_program fcode;
    u_char *pcap_userdata = 0;
#ifdef HAVE_PCAP_FINDALLDEVS
	pcap_if_t *Devices;
#endif
	char Error[PCAP_ERRBUF_SIZE];
	struct stat StatBuf;
	int i;
	int ForkBackground = TRUE;
	int ListDevices = FALSE;
	int Counter;

	ProgramStart = time(NULL);

	config.dev = NULL;
	config.filter = "ip";
	config.skip_intervals = CONFIG_GRAPHINTERVALS;
	config.graph_cutoff = CONFIG_GRAPHCUTOFF;
	config.promisc = TRUE;
	config.graph = TRUE;
	config.output_cdf = FALSE;
	config.recover_cdf = FALSE;
	config.meta_refresh = CONFIG_METAREFRESH;
	config.output_database = FALSE;
	config.db_connect_string = NULL;
	config.sensor_id = "unset";  

	openlog("bandwidthd", LOG_CONS, LOG_DAEMON);

	if (stat("/etc/bandwidthd.conf", &StatBuf))
		{
		chdir(INSTALL_DIR);
		if (stat("./etc/bandwidthd.conf", &StatBuf))
			{
			printf("Cannot find /etc/bandwidthd.conf or %s/etc/bandwidthd.conf\n", INSTALL_DIR);
			syslog(LOG_ERR, "Cannot find /etc/bandwidthd.conf or %s/etc/bandwidthd.conf", INSTALL_DIR);
			exit(1);
			}
		else
		        {
		        bdconfig_in = fopen("./etc/bandwidthd.conf", "rt");
                        }	
		}
	else
	        {
			bdconfig_in = fopen("/etc/bandwidthd.conf", "rt");
		}
		
	if (!bdconfig_in)
		{
		syslog(LOG_ERR, "Cannot open bandwidthd.conf");
		printf("Cannot open bandwidthd.conf\n");
		exit(1);
		}
	bdconfig_parse();
	/*
	// Scary
	printf("Estimated max ram utilization\nDataPoints = %.0f/%ld = %.0f\nIPData = %d * DataPoints = %.1f (%.2fKBytes) per IP\nIP_NUM = %d\nTotal = %.1fMBytes * 4 to 8 = %.1fMBytes to %.1fMBytes\n", 
		RANGE1, INTERVAL1, RANGE1/INTERVAL1,		
		sizeof(struct IPData), 
		(float) sizeof(struct IPData)*(RANGE1/INTERVAL1), 
		(float) (sizeof(struct IPData)*(RANGE1/INTERVAL1))/1024.0,
		IP_NUM, 
		(float)((sizeof(struct IPData)*(RANGE1/INTERVAL1)*IP_NUM)/1024.0)/1024.0,
		(float)4*((sizeof(struct IPData)*(RANGE1/INTERVAL1)*IP_NUM)/1024.0)/1024.0,
		(float)8*((sizeof(struct IPData)*(RANGE1/INTERVAL1)*IP_NUM)/1024.0)/1024.0);
	printf("Sizeof unsigned long: %d, sizeof unsigned long long: %d\n%lu, %llu\n",
		sizeof(unsigned long), sizeof (unsigned long long),
		(unsigned long) (0-1), (unsigned long long) (0-1));
		exit(1);
	*/
	chdir(INSTALL_DIR);

	for(Counter = 1; Counter < argc; Counter++)
		{
		if (argv[Counter][0] == '-')
			{
			switch(argv[Counter][1])
				{
				case 'D':
					ForkBackground = FALSE;
					break;
				case 'l':
					ListDevices = TRUE; 
			 		break;
				default:
					printf("Improper argument: %s\n", argv[Counter]);
					exit(1);
				}
			}
		}

#ifdef HAVE_PCAP_FINDALLDEVS
	pcap_findalldevs(&Devices, Error);
	if (Devices == NULL)
		{
		printf("Can't find network devices: %s", Error);
		exit(1);
		}
	if (config.dev == NULL && Devices->name)
		config.dev = strdup(Devices->name);
	if (ListDevices)
		{	
		while(Devices)
			{
			printf("Description: %s\nName: \"%s\"\n\n", Devices->description, Devices->name);
			Devices = Devices->next;
			}
		exit(0);
		}
#else
	if (ListDevices)
		{
		printf("List devices is not supported by you version of libpcap\n");
		exit(0);
		}
#endif	

	if (config.graph)
		{
		bd_CollectingData("htdocs/index.html");
		bd_CollectingData("htdocs/index2.html");
		bd_CollectingData("htdocs/index3.html");
		bd_CollectingData("htdocs/index4.html");
		}

	/* detach from console. */
	if (ForkBackground)
		if (fork2())
			exit(0);

	makepidfile(getpid());

	setchildconfig(0); /* initialize first (day graphing) process config */

	if (config.graph || config.output_cdf)
		{
		/* fork processes for week, month and year graphing. */
		for (i=0; i<NR_WORKER_CHILDS; i++) 
			{
			workerchildpids[i] = fork();

			/* initialize children and let them start doing work,
			 * while parent continues to fork children.
			 */

			if (workerchildpids[i] == 0) 
				{ /* child */
				setchildconfig(i+1);
				break;
				}

			if (workerchildpids[i] == -1) 
				{ /* fork failed */
				syslog(LOG_ERR, "Failed to fork graphing child (%d)", i);
				/* i--; ..to retry? -> possible infinite loop */
				continue;
				}
			}

	    if(config.recover_cdf)
		    RecoverDataFromCDF();
		}	

    IntervalStart = time(NULL);

	syslog(LOG_INFO, "Opening %s", config.dev);	
	pd = pcap_open_live(config.dev, 100, config.promisc, 1000, Error);
        if (pd == NULL) 
			{
			syslog(LOG_ERR, "%s", Error);
			exit(0);
			}

    if (pcap_compile(pd, &fcode, config.filter, 1, 0) < 0)
		{
        pcap_perror(pd, "Error");
		printf("Malformed libpcap filter string in bandwidthd.conf\n");
		syslog(LOG_ERR, "Malformed libpcap filter string in bandwidthd.conf");
		exit(1);
		}

    if (pcap_setfilter(pd, &fcode) < 0)
        pcap_perror(pd, "Error");

	switch (DataLink = pcap_datalink(pd))
		{
		default:
			if (config.dev)
				printf("Unknown Datalink Type %d, defaulting to ethernet\nPlease forward this error message and a packet sample (captured with \"tcpdump -i %s -s 2000 -n -w capture.cap\") to hinkle@derbyworks.com\n", DataLink, config.dev);
			else
				printf("Unknown Datalink Type %d, defaulting to ethernet\nPlease forward this error message and a packet sample (captured with \"tcpdump -s 2000 -n -w capture.cap\") to hinkle@derbyworks.com\n", DataLink);
			syslog(LOG_INFO, "Unkown datalink type, defaulting to ethernet");
		case DLT_EN10MB:
			syslog(LOG_INFO, "Packet Encoding: Ethernet");
			IP_Offset = 14; //IP_Offset = sizeof(struct ether_header);
			break;	
#ifdef DLT_LINUX_SLL 
		case DLT_LINUX_SLL:
			syslog(LOG_INFO, "Packet Encoding: Linux Cooked Socket");
			IP_Offset = 16;
			break;
#endif
#ifdef DLT_RAW
		case DLT_RAW:
			printf("Untested Datalink Type %d\nPlease report to hinkle@derbyworks.net if bandwidthd works for you\non this interface\n", DataLink);
			printf("Packet Encoding:\n\tRaw\n");
			syslog(LOG_INFO, "Untested packet encoding: Raw");
			IP_Offset = 0;
			break;
#endif
		case DLT_IEEE802:
			printf("Untested Datalink Type %d\nPlease report to hinkle@derbyworks.net if bandwidthd works for you\non this interface\n", DataLink);
			printf("Packet Encoding:\nToken Ring\n");
			syslog(LOG_INFO, "Untested packet encoding: Token Ring");
			IP_Offset = 22;
			break;
		}

	if (ForkBackground)
		{                                           
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		}

	signal(SIGHUP, signal_handler);
	signal(SIGTERM, signal_handler);

	if (IPDataStore)  // If there is data in the datastore draw some initial graphs
		{
		syslog(LOG_INFO, "Drawing initial graphs");
		WriteOutWebpages(IntervalStart+config.interval);
		}

    if (pcap_loop(pd, -1, PacketCallback, pcap_userdata) < 0) {
        syslog(LOG_ERR, "Bandwidthd: pcap_loop: %s",  pcap_geterr(pd));
        exit(1);
        }

    pcap_close(pd);
    exit(0);        
    }
   
void PacketCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
    {
    unsigned int counter;

    u_int caplen = h->caplen;
    const struct ip *ip;

    uint32_t srcip;
    uint32_t dstip;

    struct IPData *ptrIPData;

    if (h->ts.tv_sec > IntervalStart + config.interval)  // Then write out this intervals data and possibly kick off the grapher
        {
        GraphIntervalCount++;
        CommitData(IntervalStart+config.interval);
		IpCount = 0;
        IntervalStart=h->ts.tv_sec;
        }

    caplen -= IP_Offset;  // We're only measuring ip size, so pull off the ethernet header
    p += IP_Offset; // Move the pointer past the datalink header

    ip = (const struct ip *)p; // Point ip at the ip header

	if (ip->ip_v != 4) // then not an ip packet so skip it
		return;

    srcip = ntohl(*(uint32_t *) (&ip->ip_src));
    dstip = ntohl(*(uint32_t *) (&ip->ip_dst));
	
    for (counter = 0; counter < SubnetCount; counter++)
        {	 
		// Packets from a monitored subnet to a monitored subnet will be
		// credited to both ip's

        if (SubnetTable[counter].ip == (srcip & SubnetTable[counter].mask))
            {
            ptrIPData = FindIp(srcip);  // Return or create this ip's data structure
			if (ptrIPData)
	            Credit(&(ptrIPData->Send), ip);

            ptrIPData = FindIp(0);  // Totals
			if (ptrIPData)
	            Credit(&(ptrIPData->Send), ip);
            }
    
        if (SubnetTable[counter].ip == (dstip & SubnetTable[counter].mask))
            {
            ptrIPData = FindIp(dstip);
    		if (ptrIPData)
		        Credit(&(ptrIPData->Receive), ip);

            ptrIPData = FindIp(0);
    		if (ptrIPData)
		        Credit(&(ptrIPData->Receive), ip);
            }                        
        }
    }

inline void Credit(struct Statistics *Stats, const struct ip *ip)
    {
    unsigned long size;
    const struct tcphdr *tcp;
    uint16_t sport, dport;

    size = ntohs(ip->ip_len);

    Stats->total += size;
    
    switch(ip->ip_p)
        {
        case 6:     // TCP
            tcp = (struct tcphdr *)(ip+1);
			tcp = (struct tcphdr *) ( ((char *)tcp) + ((ip->ip_hl-5)*4) ); // Compensate for IP Options
            Stats->tcp += size;
            sport = ntohs(tcp->TCPHDR_SPORT);
            dport = ntohs(tcp->TCPHDR_DPORT);			
            if (sport == 80 || dport == 80 || sport == 443 || dport == 443)
                Stats->http += size;
	
			if (sport == 20 || dport == 20 || sport == 21 || dport == 21)
				Stats->ftp += size;

            if ( sport == 25 || dport == 25 || sport == 465 || dport == 465 || sport == 587 || dport == 587)   // IN and OUT email
                Stats->p2p += size;
            break;
        case 17:
            Stats->udp += size;
            break;
        case 1: 
            Stats->icmp += size;
            break;
        }
    }

// TODO:  Throw away old data!
void DropOldData(long int timestamp) 	// Go through the ram datastore and dump old data
	{
	struct IPDataStore *DataStore;
	struct IPDataStore *PrevDataStore;	
	struct DataStoreBlock *DeletedBlock;
	
	PrevDataStore = NULL;
    DataStore = IPDataStore;

	// Progress through the linked list until we reach the end
	while(DataStore)  // we have data
		{
		// If the First block is out of date, purge it, if it is the only block
		// purge the node
        while(DataStore->FirstBlock->LatestTimestamp < timestamp - config.range)
			{
            if ((!DataStore->FirstBlock->Next) && PrevDataStore) // There is no valid block of data for this ip, so unlink the whole ip
				{ 												// Don't bother unlinking the ip if it's the first one, that's to much
																// Trouble
				PrevDataStore->Next = DataStore->Next;	// Unlink the node
				free(DataStore->FirstBlock->Data);      // Free the memory
				free(DataStore->FirstBlock);
				free(DataStore);												
				DataStore = PrevDataStore->Next;	// Go to the next node
				if (!DataStore) return; // We're done
				}				
			else if (!DataStore->FirstBlock->Next)
				{
				// There is no valid block of data for this ip, and we are 
				// the first ip, so do nothing 
				break; // break out of this loop so the outside loop increments us
				} 
			else // Just unlink this block
				{
				DeletedBlock = DataStore->FirstBlock;
				DataStore->FirstBlock = DataStore->FirstBlock->Next;	// Unlink the block
				free(DeletedBlock->Data);
				free(DeletedBlock);
			    }
			}

		PrevDataStore = DataStore;				
		DataStore = DataStore->Next;
		}
	}

void StoreIPDataInPostgresql(struct IPData IncData[])
	{
#ifdef HAVE_LIBPQ
	struct IPData *IPData;
	unsigned int counter;
	struct Statistics *Stats;
    PGresult   *res;
	static PGconn *conn = NULL;
	static char sensor_id[50];
	const char *paramValues[10];
	char *sql1; 
	char *sql2;
	char Values[10][50];

	if (!config.output_database == DB_PGSQL)
		return;

	paramValues[0] = Values[0];
	paramValues[1] = Values[1];
	paramValues[2] = Values[2];
	paramValues[3] = Values[3];	
	paramValues[4] = Values[4];
	paramValues[5] = Values[5];
	paramValues[6] = Values[6];
	paramValues[7] = Values[7];
	paramValues[8] = Values[8];
	paramValues[9] = Values[9];

	// ************ Inititialize the db if it's not already
	if (!conn)
		{
		/* Connect to the database */
    	conn = PQconnectdb(config.db_connect_string);

	    /* Check to see that the backend connection was successfully made */
    	if (PQstatus(conn) != CONNECTION_OK)
        	{
	       	syslog(LOG_ERR, "Connection to database '%s' failed: %s", config.db_connect_string, PQerrorMessage(conn));
    	    PQfinish(conn);
        	conn = NULL;
	        return;
    	    }

		strncpy(Values[0], config.sensor_id, 50);
		res = PQexecParams(conn, "select sensor_id from sensors where sensor_name = $1;",
			1,       /* one param */
            NULL,    /* let the backend deduce param type */
   	        paramValues,
       	    NULL,    /* don't need param lengths since text */
           	NULL,    /* default to all text params */
            0);      /* ask for binary results */
		
   		if (PQresultStatus(res) != PGRES_TUPLES_OK)
       		{
        	syslog(LOG_ERR, "Postresql SELECT failed: %s", PQerrorMessage(conn));
    	    PQclear(res);
   	    	PQfinish(conn);
    	    conn = NULL;
       		return;
	        }

		if (PQntuples(res))
			{
			strncpy(sensor_id, PQgetvalue(res, 0, 0), 50);
			PQclear(res);
			}
		else
			{
			// Insert new sensor id
			PQclear(res);
			res = PQexecParams(conn, "insert into sensors (sensor_name, last_connection) VALUES ($1, now());",
				1,       /* one param */
    	        NULL,    /* let the backend deduce param type */
   	    	    paramValues,
       	    	NULL,    /* don't need param lengths since text */
				NULL,    /* default to all text params */
            	0);      /* ask for binary results */

    		if (PQresultStatus(res) != PGRES_COMMAND_OK)
        		{
	        	syslog(LOG_ERR, "Postresql INSERT failed: %s", PQerrorMessage(conn));
	    	    PQclear(res);
    	    	PQfinish(conn);
	    	    conn = NULL;
        		return;
		        }
			PQclear(res);
			res = PQexecParams(conn, "select sensor_id from sensors where sensor_name = $1;",
				1,       /* one param */
        	    NULL,    /* let the backend deduce param type */
   	        	paramValues,
	       	    NULL,    /* don't need param lengths since text */
    	       	NULL,    /* default to all text params */
        	    0);      /* ask for binary results */
		
	   		if (PQresultStatus(res) != PGRES_TUPLES_OK)
    	   		{
        		syslog(LOG_ERR, "Postresql SELECT failed: %s", PQerrorMessage(conn));
    	    	PQclear(res);
	   	    	PQfinish(conn);
    		    conn = NULL;
       			return;
	        	}
			strncpy(sensor_id, PQgetvalue(res, 0, 0), 50);
			PQclear(res);
			}	
		}

	// Begin transaction

	// **** Perform inserts
	res = PQexecParams(conn, "BEGIN;",
			0,       /* zero param */
    	    NULL,    /* let the backend deduce param type */
   	    	NULL,
	    	NULL,    /* don't need param lengths since text */
			NULL,    /* default to all text params */
       		0);      /* ask for binary results */

 	if (PQresultStatus(res) != PGRES_COMMAND_OK)
    	{
	    syslog(LOG_ERR, "Postresql BEGIN failed: %s", PQerrorMessage(conn));
	    PQclear(res);
    	PQfinish(conn);
	    conn = NULL;
        return;
		}							
	PQclear(res);

	strncpy(Values[0], sensor_id, 50);

	res = PQexecParams(conn, "update sensors set last_connection = now() where sensor_id = $1;",
			1,       /* one param */
    	    NULL,    /* let the backend deduce param type */
   	    	paramValues,
	    	NULL,    /* don't need param lengths since text */
			NULL,    /* default to all text params */
       		0);      /* ask for binary results */

 	if (PQresultStatus(res) != PGRES_COMMAND_OK)
    	{
	    syslog(LOG_ERR, "Postresql UPDATE failed: %s", PQerrorMessage(conn));
	    PQclear(res);
    	PQfinish(conn);
	    conn = NULL;
        return;
		}							
	PQclear(res);

	Values[0][49] = '\0';
	snprintf(Values[1], 50, "%llu", config.interval);
	for (counter=0; counter < IpCount; counter++)
		{
        IPData = &IncData[counter];

		if (IPData->ip == 0)
			{
			// This optimization allows us to quickly draw totals graphs for a sensor
			sql1 = "INSERT INTO bd_tx_total_log (sensor_id, sample_duration, ip, total, icmp, udp, tcp, ftp, http, p2p) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);";
			sql2 = "INSERT INTO bd_rx_total_log (sensor_id, sample_duration, ip, total, icmp, udp, tcp, ftp, http, p2p) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);";
			}
		else
			{
			sql1 = "INSERT INTO bd_tx_log (sensor_id, sample_duration, ip, total, icmp, udp, tcp, ftp, http, p2p) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);";
			sql2 = "INSERT INTO bd_rx_log (sensor_id, sample_duration, ip, total, icmp, udp, tcp, ftp, http, p2p) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);"; 
			}

        HostIp2CharIp(IPData->ip, Values[2]);

		Stats = &(IPData->Send);
		if (Stats->total > 512) // Don't log empty sets
			{
			// Log data in kilobytes
			snprintf(Values[3], 50, "%llu", (long long unsigned int)((((double)Stats->total)/1024.0) + 0.5));
			snprintf(Values[4], 50, "%llu", (long long unsigned int)((((double)Stats->icmp)/1024.0) + 0.5));
			snprintf(Values[5], 50, "%llu", (long long unsigned int)((((double)Stats->udp)/1024.0) + 0.5));
			snprintf(Values[6], 50, "%llu", (long long unsigned int)((((double)Stats->tcp)/1024.0) + 0.5));
			snprintf(Values[7], 50, "%llu", (long long unsigned int)((((double)Stats->ftp)/1024.0) + 0.5));
			snprintf(Values[8], 50, "%llu", (long long unsigned int)((((double)Stats->http)/1024.0) + 0.5));
			snprintf(Values[9], 50, "%llu", (long long unsigned int)((((double)Stats->p2p)/1024.0) + 0.5));

			res = PQexecParams(conn, sql1,
				10,       /* nine param */
	            NULL,    /* let the backend deduce param type */
    	        paramValues,
        	    NULL,    /* don't need param lengths since text */
            	NULL,    /* default to all text params */
	            1);      /* ask for binary results */

    		if (PQresultStatus(res) != PGRES_COMMAND_OK)
        		{
	        	syslog(LOG_ERR, "Postresql INSERT failed: %s", PQerrorMessage(conn));
	    	    PQclear(res);
    	    	PQfinish(conn);
	    	    conn = NULL;
        		return;
		        }
			PQclear(res);
			}
		Stats = &(IPData->Receive);
		if (Stats->total > 512) // Don't log empty sets
			{
			snprintf(Values[3], 50, "%llu", (long long unsigned int)((((double)Stats->total)/1024.0) + 0.5));
			snprintf(Values[4], 50, "%llu", (long long unsigned int)((((double)Stats->icmp)/1024.0) + 0.5));
			snprintf(Values[5], 50, "%llu", (long long unsigned int)((((double)Stats->udp)/1024.0) + 0.5));
			snprintf(Values[6], 50, "%llu", (long long unsigned int)((((double)Stats->tcp)/1024.0) + 0.5));
			snprintf(Values[7], 50, "%llu", (long long unsigned int)((((double)Stats->ftp)/1024.0) + 0.5));
			snprintf(Values[8], 50, "%llu", (long long unsigned int)((((double)Stats->http)/1024.0) + 0.5));
			snprintf(Values[9], 50, "%llu", (long long unsigned int)((((double)Stats->p2p)/1024.0) + 0.5));

			res = PQexecParams(conn, sql2,
				10,       /* seven param */
            	NULL,    /* let the backend deduce param type */
	            paramValues,
    	        NULL,    /* don't need param lengths since text */
        	    NULL,    /* default to all text params */
            	1);      /* ask for binary results */

	    	if (PQresultStatus(res) != PGRES_COMMAND_OK)
    	    	{
	    	    syslog(LOG_ERR, "Postresql INSERT failed: %s", PQerrorMessage(conn));
    	    	PQclear(res);
	        	PQfinish(conn);
		        conn = NULL;
        		return;
	        	}
			PQclear(res);
			}		
		}
	// Commit transaction
	res = PQexecParams(conn, "COMMIT;",
			0,       /* zero param */
    	    NULL,    /* let the backend deduce param type */
   	    	NULL,
	    	NULL,    /* don't need param lengths since text */
			NULL,    /* default to all text params */
       		0);      /* ask for binary results */

 	if (PQresultStatus(res) != PGRES_COMMAND_OK)
    	{
	    syslog(LOG_ERR, "Postresql COMMIT failed: %s", PQerrorMessage(conn));
	    PQclear(res);
    	PQfinish(conn);
	    conn = NULL;
        return;
		}							
	PQclear(res);
#else
	syslog(LOG_ERR, "Postgresql logging selected but postgresql support is not compiled into binary.  Please check the documentation in README, distributed with this software.");
#endif
	}

void StoreIPDataInDatabase(struct IPData IncData[])
	{
	if (config.output_database == DB_PGSQL)
		StoreIPDataInPostgresql(IncData);
	else if(config.output_database == DB_SQLITE)
		sqliteStoreIPData(IncData);
	}

void StoreIPDataInCDF(struct IPData IncData[])
	{
	struct IPData *IPData;
	unsigned int counter;
	FILE *cdf;
	struct Statistics *Stats;
	char IPBuffer[50];
	char logfile[] = "log.1.0.cdf";
	
	logfile[4] = config.tag;	

   	cdf = fopen(logfile, "at");

	for (counter=0; counter < IpCount; counter++)
		{
		IPData = &IncData[counter];
		HostIp2CharIp(IPData->ip, IPBuffer);
		fprintf(cdf, "%s,%lu,", IPBuffer, IPData->timestamp);
		Stats = &(IPData->Send);
		fprintf(cdf, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,", Stats->total, Stats->icmp, Stats->udp, Stats->tcp, Stats->ftp, Stats->http, Stats->p2p); 
		Stats = &(IPData->Receive);
		fprintf(cdf, "%llu,%llu,%llu,%llu,%llu,%llu,%llu\n", Stats->total, Stats->icmp, Stats->udp, Stats->tcp, Stats->ftp, Stats->http, Stats->p2p); 		
		}
	fclose(cdf);
	}

void _StoreIPDataInRam(struct IPData *IPData)
	{
	struct IPDataStore *DataStore;
	struct DataStoreBlock *DataStoreBlock;

	if (!IPDataStore) // we need to create the first entry
		{
		// Allocate Datastore for this IP
	    IPDataStore = malloc(sizeof(struct IPDataStore));
			
		IPDataStore->ip = IPData->ip;
		IPDataStore->Next = NULL;
					
		// Allocate it's first block of storage
		IPDataStore->FirstBlock = malloc(sizeof(struct DataStoreBlock));
		IPDataStore->FirstBlock->LatestTimestamp = 0;

		IPDataStore->FirstBlock->NumEntries = 0;
		IPDataStore->FirstBlock->Data = calloc(IPDATAALLOCCHUNKS, sizeof(struct IPData));
		IPDataStore->FirstBlock->Next = NULL;																		
        if (!IPDataStore->FirstBlock || ! IPDataStore->FirstBlock->Data)
            {
            syslog(LOG_ERR, "Could not allocate datastore! Exiting!");
            exit(1);
            }
		}

	DataStore = IPDataStore;

	// Take care of first case
	while (DataStore) // Is not null
		{
		if (DataStore->ip == IPData->ip) // then we have the right store
			{
			DataStoreBlock = DataStore->FirstBlock;

			while(DataStoreBlock) // is not null
				{
				if (DataStoreBlock->NumEntries < IPDATAALLOCCHUNKS) // We have a free spot
					{
					memcpy(&DataStoreBlock->Data[DataStoreBlock->NumEntries++], IPData, sizeof(struct IPData));
					DataStoreBlock->LatestTimestamp = IPData->timestamp;
					return;
					}
        	    else
					{
					if (!DataStoreBlock->Next) // there isn't another block, add one
						{
	                    DataStoreBlock->Next = malloc(sizeof(struct DataStoreBlock));
						DataStoreBlock->Next->LatestTimestamp = 0;
						DataStoreBlock->Next->NumEntries = 0;
						DataStoreBlock->Next->Data = calloc(IPDATAALLOCCHUNKS, sizeof(struct IPData));
						DataStoreBlock->Next->Next = NULL;																				
						}

					DataStoreBlock = DataStoreBlock->Next;
					}
				}						

			return;
			}
		else
			{
			if (!DataStore->Next) // there is no entry for this ip, so lets make one.
				{
				// Allocate Datastore for this IP
    	        DataStore->Next = malloc(sizeof(struct IPDataStore));
				
			    DataStore->Next->ip = IPData->ip;
				DataStore->Next->Next = NULL;
					
				// Allocate it's first block of storage
				DataStore->Next->FirstBlock = malloc(sizeof(struct DataStoreBlock));
				DataStore->Next->FirstBlock->LatestTimestamp = 0;
				DataStore->Next->FirstBlock->NumEntries = 0;
				DataStore->Next->FirstBlock->Data = calloc(IPDATAALLOCCHUNKS, sizeof(struct IPData));
				DataStore->Next->FirstBlock->Next = NULL;																		
				}
	
			DataStore = DataStore->Next;			
			}
		}
	}

void StoreIPDataInRam(struct IPData IncData[])
	{
	unsigned int counter;

    for (counter=0; counter < IpCount; counter++)
		_StoreIPDataInRam(&IncData[counter]);
	}

void CommitData(time_t timestamp)
    {
	static int MayGraph = TRUE;
    unsigned int counter;
	struct stat StatBuf;
	char logname1[] = "log.1.5.cdf";
	char logname2[] = "log.1.4.cdf";
	// Set the timestamps
	for (counter=0; counter < IpCount; counter++)
        IpTable[counter].timestamp = timestamp;

	// Output modules
	// Only call this from first thread
	if (config.output_database && config.tag == '1')
		StoreIPDataInDatabase(IpTable);

	if (config.output_cdf)
		{
		// TODO: This needs to be moved into the forked section, but I don't want to 
		//	deal with that right now (Heavy disk io may make us drop packets)
		StoreIPDataInCDF(IpTable);

		if (RotateLogs >= config.range/RANGE1) // We set this++ on HUP
			{
			logname1[4] = config.tag;
			logname2[4] = config.tag;
			logname2[6] = '5';

			if (!stat(logname2, &StatBuf)) // File exists
				unlink(logname2);
			logname1[6] = '4';
			if (!stat(logname1, &StatBuf)) // File exists
				rename(logname1, logname2);
			logname1[6] = '3';
			logname2[6] = '4';			
			if (!stat(logname1, &StatBuf)) // File exists
				rename(logname1, logname2);
            logname1[6] = '2';
            logname2[6] = '3';			
			if (!stat(logname1, &StatBuf)) // File exists
				rename(logname1, logname2);
            logname1[6] = '1';
            logname2[6] = '2';			
			if (!stat(logname1, &StatBuf)) // File exists
				rename(logname1, logname2);
            logname1[6] = '0';
            logname2[6] = '1';			
			if (!stat(logname1, &StatBuf)) // File exists
				rename(logname1, logname2); 
			fclose(fopen(logname1, "at")); // Touch file
			RotateLogs = FALSE;
			}
		}

	if (config.graph)
		{
		StoreIPDataInRam(IpTable);

		// Reap a couple zombies
		if (waitpid(-1, NULL, WNOHANG))  // A child was reaped
			MayGraph = TRUE;

		if (GraphIntervalCount%config.skip_intervals == 0 && MayGraph)
			{
			MayGraph = FALSE;
			/* If WriteOutWebpages fails, reenable graphing since there won't
			 * be any children to reap.
			 */
			if (WriteOutWebpages(timestamp))
				MayGraph = TRUE;
			}
		else if (GraphIntervalCount%config.skip_intervals == 0)
			syslog(LOG_INFO, "Previouse graphing run not complete... Skipping current run");

		DropOldData(timestamp);
		}
    }


int RCDF_Test(char *filename)
	{
	// Determine if the first date in the file is before the cutoff
	// return FALSE on error
	FILE *cdf;
	char ipaddrBuffer[16];
	time_t timestamp;

	if (!(cdf = fopen(filename, "rt"))) 
		return FALSE;
	fseek(cdf, 10, SEEK_END); // fseek to near end of file
	while (fgetc(cdf) != '\n') // rewind to last newline
		{
		if (fseek(cdf, -2, SEEK_CUR) == -1)
			break;
		}
	if(fscanf(cdf, " %15[0-9.],%lu,", ipaddrBuffer, &timestamp) != 2)
		{
		syslog(LOG_ERR, "%s is corrupted, skipping", filename); 
		return FALSE;
		}
	fclose(cdf);
	if (timestamp < time(NULL) - config.range)
		return FALSE; // There is no data in this file from before cutoff
	else
		return TRUE; // This file has data from before cutoff
	}


void RCDF_PositionStream(FILE *cdf)
	{
    time_t timestamp;
	time_t current_timestamp;
	char ipaddrBuffer[16];

	current_timestamp = time(NULL);

	fseek(cdf, 0, SEEK_END);
	timestamp = current_timestamp;
	while (timestamp > current_timestamp - config.range)
		{
		// What happenes if we seek past the beginning of the file?
		if (fseek(cdf, -IP_NUM*75*(config.range/config.interval)/20,SEEK_CUR))
			{ // fseek returned error, just seek to beginning
			fseek(cdf, 0, SEEK_SET);
			return;
			}
		while (fgetc(cdf) != '\n' && !feof(cdf)); // Read to next line
		ungetc('\n', cdf);  // Just so the fscanf mask stays identical
        if(fscanf(cdf, " %15[0-9.],%lu,", ipaddrBuffer, &timestamp) != 2)
			{
			syslog(LOG_ERR, "Unknown error while scanning for beginning of data...\n");
			return;	
			}
		}
	while (fgetc(cdf) != '\n' && !feof(cdf));
	ungetc('\n', cdf); 
	}

void RCDF_Load(FILE *cdf)
	{
    time_t timestamp;
	time_t current_timestamp = 0;
	struct in_addr ipaddr;
	struct IPData *ip=NULL;
	char ipaddrBuffer[16];
	unsigned long int Counter = 0;
	unsigned long int IntervalsRead = 0;

    for(Counter = 0; !feof(cdf) && !ferror(cdf); Counter++)
	    {
		if(fscanf(cdf, " %15[0-9.],%lu,", ipaddrBuffer, &timestamp) != 2) 
			goto End_RecoverDataFromCdf;

		if (!timestamp) // First run through loop
			current_timestamp = timestamp;

		if (timestamp != current_timestamp)
			{ // Dump to datastore
			StoreIPDataInRam(IpTable);
			IpCount = 0; // Reset Traffic Counters
			current_timestamp = timestamp;
			IntervalsRead++;
			}    		
		inet_aton(ipaddrBuffer, &ipaddr);
		ip = FindIp(ntohl(ipaddr.s_addr));
		ip->timestamp = timestamp;

        if (fscanf(cdf, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,",
            &ip->Send.total, &ip->Send.icmp, &ip->Send.udp,
            &ip->Send.tcp, &ip->Send.ftp, &ip->Send.http, &ip->Send.p2p) != 7
          || fscanf(cdf, "%llu,%llu,%llu,%llu,%llu,%llu,%llu",
            &ip->Receive.total, &ip->Receive.icmp, &ip->Receive.udp,
            &ip->Receive.tcp, &ip->Receive.ftp, &ip->Receive.http, &ip->Receive.p2p) != 7)
			goto End_RecoverDataFromCdf;		
		}

End_RecoverDataFromCdf:
	StoreIPDataInRam(IpTable);
	syslog(LOG_INFO, "Finished recovering %lu records", Counter);	
	DropOldData(time(NULL)); // Dump the extra data
    if(!feof(cdf))
       syslog(LOG_ERR, "Failed to parse part of log file. Giving up on the file");
	IpCount = 0; // Reset traffic counters
    fclose(cdf);
	}

void RecoverDataFromCDF(void)
	{
	FILE *cdf;
	char index[] = "012345";
    char logname1[] = "log.1.0.cdf";
    char logname2[] = "log.1.1.cdf";
	int Counter;
	int First = FALSE;

	logname1[4] = config.tag;
	logname2[4] = config.tag;

	for (Counter = 5; Counter >= 0; Counter--)
		{
		logname1[6] = index[Counter];
		if (RCDF_Test(logname1))
			break;
		}
	
	First = TRUE;
	for (; Counter >= 0; Counter--)
		{
		logname1[6] = index[Counter];
		if ((cdf = fopen(logname1, "rt")))
			{
			syslog(LOG_INFO, "Recovering from %s", logname1);
			if (First)
				{
				RCDF_PositionStream(cdf);
				First = FALSE;
				}
			RCDF_Load(cdf);
			}
		}
	}

// ****** FindIp **********
// ****** Returns or allocates an Ip's data structure

inline struct IPData *FindIp(uint32_t ipaddr)
    {
    unsigned int counter;
    
    for (counter=0; counter < IpCount; counter++)
        if (IpTable[counter].ip == ipaddr)
            return (&IpTable[counter]);
    
    if (IpCount >= IP_NUM)
        {
        syslog(LOG_ERR, "IP_NUM is too low, dropping ip....");
       	return(NULL);
        }
	
    memset(&IpTable[IpCount], 0, sizeof(struct IPData));

    IpTable[IpCount].ip = ipaddr;
    return (&IpTable[IpCount++]);
    }

size_t ICGrandTotalDataPoints = 0;

__attribute__ ((gnu_inline)) char inline *HostIp2CharIp(unsigned long ipaddr, char *buffer)
    {
	struct in_addr in_addr;
	char *s;

	in_addr.s_addr = htonl(ipaddr);	
    s = inet_ntoa(in_addr);
	strncpy(buffer, s, 16);
	buffer[15] = '\0';
	return(buffer);
/*  uint32_t ip = *(uint32_t *)ipaddr;

	sprintf(buffer, "%d.%d.%d.%d", (ip << 24)  >> 24, (ip << 16) >> 24, (ip << 8) >> 24, (ip << 0) >> 24);
*/
    }

// Add better error checking

int fork2()
    {
    pid_t pid;

    if (!(pid = fork()))
        {
        if (!fork())
        	{
#ifdef PROFILE
				// Got this incantation from a message board.  Don't forget to set
				// GMON_OUT_PREFIX in the shell
				extern void _start(void), etext(void);
				syslog(LOG_INFO, "Calling profiler startup...");
				monstartup((u_long) &_start, (u_long) &etext);
#endif
            return(0);
            }        

        _exit(0);
        }
    
    waitpid(pid, NULL, 0);
    return(1);
    }

