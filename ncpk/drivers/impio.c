#
#include "param.h"
#include "user.h"
#include "buf.h"
#include "net_net.h"
#include "net_netbuf.h"
#include "net_imp.h"
#include "net_hosthost.h"
#include "proc.h"
#include "file.h"
#include "net_ncp.h"
#include "net_contab.h"


#ifdef IMPPRTDEBUG
int	impdebug 0;
#endif	/* JC McMillan */

struct netbuf *rathole;		/* net buffer for discards */
struct netbuf *impi_msg; /* pts to msg being built by imp read */
int     impi_con;       /* pointer to rawent jsq BBN 3-21-79 */

#ifdef SCCSID
/* SCCS PROGRAM IDENTIFICATION STRING */
/*char id_impio[] "~|^`impio.c\tV3.9E1\t25Jan78\n";*/
#endif SCCSID

/* this array is indexed by the above op codes to give the length of the command */

char hhsize[14]
{
	1,		/* nop */
	10,		/* rts */
	10,		/* str */
	9,		/* cls */
	8,		/* all */
	4,		/* gvb */
	8,		/* ret */
	2,		/* inr */
	2,		/* ins */
	2,		/* eco */
	2,		/* erp */
	12,		/* err */
	1,		/* rst */
	1		/* rrp */
};

/* this array holds the rfnm wait bits for sending allocations to hosts */
char host_map[32];


/*name:
	impopen

function:
	imp input process

algorithm:
	fork a kernel process to handle input from net
	child:
		close parents files
	loop:
		init imp interface on first pass thru loop
		and send the noops
		read header
		if no error,
		call parse routine, which will read in rest of message
		else restart interface
		go to loop

parameters:
	none

returns:
	nothing

globals:
	ncpopnstate

calls:
	imp_init
	sleep(sys)
	newproc(sys)
	impread
	imp_input
	imp_reset
	impopen
	impstrat
	spl_imp

called by:
	ncpopen
	(ncpclose	awakens this code)
	(imp_iint	awakens this code)

history:
	initial coding 1/7/75 by S. F. Holmgren
	modified 10/5/75 chopped initialize into imp_init
	and started checking imp_error bit and inited if
	bit was on S. F. Holmgren
	modified 04 Jan 77 for ACC LH-11 by JSK
	modifed 25Jan78 to keep smalldaemon from returning at bottom

*/
impopen()
{
	register int *fp, *p;
	int needinit, inx;

	/*
	 * shouldn't we check to see that we don't get in here twice ?
	 */

	rathole = getbuf();

	if (newproc()) {	 /* fork input process */
		/* release any hold we may have on parents files */
		for( fp = &u.u_ofile[0]; fp < &u.u_ofile[NOFILE]; fp++ )
			if( (p = *fp) != NULL ){
				p->f_count--;
				*fp = 0;
			}

		needinit = 1;	/* flag to force initialization */
		for (;;)	/* body of input process */
		{
			spl_imp();
			if (needinit) {
				needinit = 0;
				imp_init ();
				for ( inx = 0; inx < 3; inx++ ) { /* send 3 noops */
					oimp.o_type = ih_nop;	/* set opcode to h_i_nop */
					impobuf.b_addr = &oimp;	/* set addr for output */
					impobuf.b_wcount = 4;	/* send the four imp leader bytes */
					impstrat( &impobuf );	/* send one */
					iowait( &impobuf );			/* wait for one to fin */
				}
				/* set parameters on input leader */
				imp.nrcv = ncp_rcv;	/* perm receive comm here */
				printf("\nIMP:Init\n");	/*JCM*/
				impread(&imp.type, 8);	/* set up input side of imp interface */
			}
			sleep( &imp,-25 );	/* wait for something */
			if( ncpopnstate == 0 ) break;	/* we down? */
			if (imp_stat.error) {
				printf ("\nIMP: input error, resetting\n");
				imp_reset ();
				needinit++;
			}else{
				imp_input();		/* handle it */
			}
		}
		imp_dwn();		/* clean up kernel data */
		exit ();	/* imp input process never returns */
	}
}

/*name:
	imp_input

function:
	Started in response to a wakeup from the input interrupt
	initiates and switches all transfers received from the imp.

algorithm:
	There are two logical states -
	1. The driver will setup an 8 byte read from the imp when
	   it is in the leader state evidenced by impi_adr == &imp.type
	   even if there is more data to be received from the imp
	   the interface will interrupt and come here for decoding.

	2. After a leader has been received and the endmsg bit of 
	   interface is not sent, the driver falls into a data
	   buffering mode reloaded by ihbget until the endmsg
	   flag is raised.


	if buffering data
		call hh let him handle it
	else
		if leaderread and endmsg means imp to host msg received
			call ih and let him deal with that type
		else
			must be a normal leader with further data waiting in imp
			is imp pad byte != 0
				yes error do stats and flush imp
			else
				legal leader
				if hh protocol msg (imp.link == 0)
					set flag
					continue buffering data
				else
					if host & link number are in conntab
						then set ptr to associated inode
						and continue reading data
					else
						error flush imp 

parameters:
	none

returns:
	nothing

globals:
	struct imp		struct for accessing various imp leader fields
	impi_sockt=		set to addr of user inode
	impi_addr

calls:
	hh			to handle hh protocol msgs
	ih			to handle imp to host protocol msgs
	flushimp		to keep reading data until endmsg is on
	ihbget			to reload imp with fresh imp data buffer
	imphostlink		map host link number in conn tab to sktp ptr
	printf
	prt_dbg			prints debugging msg on terminal
	imp_input
	swab	(sys)


called by:
	imp_open

history:

	initial coding 1/7/75 by Steve Holmgren
	Modified by J.C.McMillan for LH-DH-11 Jan77
	Modified for modularity 04Jan77 JSK
	Suppressed Link # ? message 5Jun77 J.S.Kravitz
*/
imp_input()	/* imp input handler */
{
	register char *c;		/* does unsigned arith & general logic*/
	register char *errtext;		/* pts to 1 of several texts for errmsg */


		/* Each msg begins with a leader of 4 (imp-to-host) or
		**  9 (host-to-host) bytes.  The first read of a msg
		**  (ie, where impi_adr== &imp.type) looks at up-to the first
		**  8 bytes: a completed read indicates an I-to-H
		**  leader, and an incomplete read indicates a H-to-H
		**  where 1 byte (discardable) will be picked up on the
		**  next IMP buffer.

		** On further IMP-reads (ie, when impi_adr!= &imp.type) the
		**  hh() code takes over and concatenates the buffers.
		*/

	if (impi_adr != &imp.type)	/*...if the leader is not being read... */
		hh();		/*    data is being buffered */

		/***************************************************
		**  Prev. line called on hh() to process data     **
		**    which follows leaders:			  **
		**    Lines below process only leaders (IH/HH).   **
		***************************************************/

	else			/*...an 8 byte leader-read is being processed*/
	if (imp_stat.inpendmsg)
		ih();		/* if 'endmsg', a 4 byte IH leader is assumed */

	else			/* ...else a 9 byte HH leader is assumed*/
	if (imp.pad1 != 0)	/* if illegal leader */
	{
		errtext = "Pad error";   /* JC McMillan */
	    iherr:
		impi_sockt = 0;
		imp_stat.i_leaderr++;
		if (errtext)
			printf("\nIMP:%s\n", errtext);
#		ifdef IMPPRTDEBUG
			prt_dbg(" ", 2*(impi_wcnt+imp_stat.inpwcnt), -1, &imp.type);
#		endif	/* JC McMillan */
		flushimp();
	}

	else			/* Pad valid on HH leader */
	if (imp.link == 0)	/* if a HH protocol (link==0) */
	{	if (imp.bsize!=8 || (c=swab(imp.bcnt))>120)
		{	errtext = "HH Ldr format";   /* JC McMillan */
			goto iherr;
		}
		impi_sockt = 0;
	    nxtbuf:
#		ifdef IMPPRTDEBUG
			prt_dbg("HHl", 2*(impi_wcnt+imp_stat.inpwcnt), 3, &imp.type);   /* print 8 bytes of leader*/
#		endif	/* JC McMillan */
		ihbget();
	}

	else	/*... must be HH data msg, and link must be validated */
	if( impi_sockt = imphostlink( imp.link & 0177 ))
		goto nxtbuf;	/* got iptr cont reading */

	else	/*All else has failed! Assume HH data msg w/ invalid link*/
	{
		errtext = 0;	/* JSK 5Jun77 */
		/* errtext = "Link#?"; */
		goto iherr;	/* whos he err */
	}
}
/*name:
	hh

function:
	If data received was not an imp leader to continue buffering
	until endmsg is raised on imp interface, once raised, msg is
	switched either to user or passed to hh1 for further decoding
	and possible switching.

algorithm:
	if endmsg raised
		if flushing imp
			discard data 
			reset flushing switch
			if data for user
				indicate error 
				allow him to run
		else
		not flushing so data is either for ncp daemon or user
				decrement users byte allocation by msg size
				link msg to user msg queue
				increment users msg queue byte total
				let user run
			msg is a host to host msg call hh1 for further decoding
		start another leader read
	else
		endmsg not set so either keep buffering or flushing
		if flushing
			keep flushing
		else
			keep reading

parameters:
	none

returns:
	nothing

globals:
	impi_msg->b_len=
	impi_flush=
	sktp->r_flags=
	sktp->r_bytes=
	sktp->r_msgs=
	sktp->r_msgq
	sktp->r_qtotal=
	imp.nrcv

calls:
	freemsg			to destroy buffer data
	wakeup (sys)		to allow user to run
	rmovepad		to remove imp padding and set length
	to_ncp			to pass data to ncpdaemon
	hh1			for further decoding and switching of data
	impread			to start another leader read
	flushimp		to continue flushing data from imp
	ihbget			continue bufferin data
	prt_dbg			prints debugging msg on terminal
	catmsg			assemble incoming message
called by:
	imp_input

history:

	initial coding 1/7/75 by Steve Holmgren
	check for something in impi_msg 8/16/76 S. Holmgren
	Modified Jan77 for LH-DH-11 by JSK& JC McMillan 
	server telnet test stuff deleted 12Jun77 JSKravitz
*/

hh()
{
	register struct rdskt *sktp;
	register char *src;
	register char *dest;
	struct netbuf *bufp;
	int cnt;

	sktp = impi_sockt;
	

	if( impi_msg )		/* if there is anything in the msg */
		impi_msg->b_len = net_b_size;
			/* The above sets a maximum bound on the number of
			**	characters in the buffer... rmovepad will
			**	more accurately set this length.        */

	if (imp_stat.inpendmsg)
	{
		if( impi_flush ) 		/* finished flushing */
		{
#			ifdef IMPPRTDEBUG
				prt_dbg("   ^", net_b_size+2*imp_stat.inpwcnt, -1, rathole);
#			endif	/* JC McMillan */

			freemsg( impi_msg );	/* destroy any bfred data */
			impi_msg = 0;		/* get rid of previous msg */
			impi_flush = 0;	/* reset flushing */
			if (sktp)		/* was user proc involved */
			{
				sktp->r_flags =| n_eof;	/* set err */
				wakeup( sktp );
			}
		}
		else
		{
			/* destroy the first data byte, its part of the leader */
			bufp = impi_msg->b_qlink;
			bufp->b_len--;
			src = dest = &bufp->b_data[0];
			src++;
			cnt = net_b_size+1;
			while( --cnt )	*dest++ = *src++;

			rmovepad();		/* remove padding and set length */

			if (sktp)		/* if (sktp!=0) then its a user-lvl msg*/
			{
#				ifdef IMPPRTDEBUG
					prt_dbg("Usr<", (src=bufp->b_len) > 15 ? 15:src, 1, &bufp->b_data[0]);
#				endif	/* JC McMillan */
				if( sktp->r_flags&n_toncp)	/* data to ncp? */
					to_ncp(&imp.nrcv,5,impi_msg);
				else	/* no give to user and wakeup */
				{
					/* dec msgs allocated */
					sktp->r_msgs--;
					sktp->r_msgq = catmsg( sktp->r_msgq,impi_msg );
					sktp->r_qtotal =+ impi_mlen;
					wakeup( sktp );
				}
			}
			else	/* nope hh msg */
			{
				hh1();		/* let him handle this */
			}
		}
		impi_msg = 0;
		impread(&imp.type, 8);	/* start another leader read */
	}
	else
	if( imp_stat.inpwcnt == 0 )	/* filled our buffer? JSK */
	{
		/* not end msg - keep flushing or reading */
		if( impi_flush )	/* flushing? */
		{
#			ifdef IMPPRTDEBUG
				prt_dbg("   +", net_b_size, -1, rathole);
#			endif	/* JC McMillan */

			flushimp();	/* yes - keep flushing */
		}
		else
			ihbget();	/* no cont reading data */
	
	}
	else
		printf("\nIMP:Phantom Intrp(Csri=%o)\n", imp_stat.inpstat);
}



/*name:
	ih

function:
	To look at all imp to host messages and handle rfnms, incomplete
	transmissions, and nops

algorithm:
	if imp.type is request for next message (rfnm)
		tell user rfnm arrived
	if imp.type is nop
		start another leader read
	if imp.type is error_in_data or incomplete_transmission
		tell user last data he sent is in error or imp couldnt handle
	if imp.type is non of the above
		send imp leader to ncpdaemon for processing

	in any case start another leader read

parameters:
	none

returns:
	nothing

globals:
	imp.type
	imp.nrcv
calls:
	siguser			to let user see rfnms, incomptrans or err data
	to_ncp			to ship leaders to ncpdaemon
	impread			to start another leader read
	prt_dbg			prints debugging msg on terminal

called by:
	imp_input

history:

	initial coding 1/7/75 by Steve Holmgren
*/

ih()		/*  handles all imp to host messages */
{
	register char *p;
	
#	ifdef IMPPRTDEBUG
		prt_dbg("IH ", 8+2*imp_stat.inpwcnt, 3, &imp.type);   /* print 'N' bytes of leader (us.==4)*/
#	endif	/* JC McMillan */

	switch( imp.type )
	{
		case ih_rfnm:	siguser( n_rfnmwt );	/* tell user rfnm arrived  */
		case ih_nop:	break;		/* ignore nops */

		case ih_edata:
		case ih_ictrans:siguser( n_xmterr );	/* tell user about his problem   */
		default:	to_ncp( &imp.nrcv,5,0 );	/* send leader to ncp */

	}
	impi_msg = 0;
	impread(&imp.type, 8);		/* start another leader read */
	
}


/*name:
	siguser

function:
	ostensibly to or the parameter into the users flag field and
	let him run. If the socket is closed send a close command
	to the ncp daemon he was waiting for a msg to clear the imp sys
	If the ncp daemon is monitoring all data going to a user send
	the rfnm to him
	if this is a host to host protocol rfnm let the ncp daemon
	know he can now send further protocol msgs to that host.


algorithm:
	If imp.link!=0 andif the host link entry is in the conn tab
		If conn closed
			send close to ncpdaemon
		if data for ncpdaemon
			send leader to ncpdaemon
		else
			or param into flag field
			allow user to run
	else
		host to host protocol return response so
		allow ncpdaemon to process 

parameters:
	sigflg		bits to be ored into the users flag field

returns:
	nothing

globals:
	imp.link
	imp.nrcv
	conentry->w_flags=

calls:
	imphostlink		to relate host link to socket entry
	wakeup (sys)		to allow user to run
	to_ncp			to send data to ncp daemon
	siguser
	biton
	reset_bit

called by:
	ih

history:

	initial coding 1/7/75 by Steve Holmgren
	removed check for rfnm so incomplete transmissions 
	will also reset the host rfnm bit 8/20/76 S. Holmgren
*/

siguser( sigflg )		/* called when user needs waking up. the
				   passed flag is ored into his flag field
				   and he is awakened */
{
	register conentry;
	
	if( imp.link && (conentry = imphostlink( imp.link | 0200 )) )
	{
			if( conentry->w_flags & n_toncp )
				to_ncp( &imp.nrcv,5,0 );	/* give to ncp */
			else
			{
				conentry->w_flags =| sigflg;	/* set flags */
				wakeup( conentry );
			}
	}
	else
	{
		/* user waiting for control link rfnm? */
		if( bit_on( host_map,imp.host ) != 0 )
		{
			/* say rfnm here */
			reset_bit( host_map,imp.host );
			/* let any users battle it out */
			wakeup( host_map+imp.host );
		}
		else
			/* no users waiting ship to daemon */
			to_ncp( &imp.nrcv,5,0 );
	
	}
}


/*name:
	prt_dbg

function:
	To print debugging data in a consistent manner.


parameters:
	str -- A string of length <= 3, used as first text on line.
	cnt -- The count of the number of bytes to print.
	typ -- The extended interpretation type:
		1 - general data
		2 - HH protocol data
		3 - imp leader data
		Negative # indicates MANDATORY printf, regardless of impdebug flag
	adr -- The address from which to start printing bytes.

returns:
	nothing

globals:
	impdebug		 iff, print debugging information 

calls:
	printf

called by:
	ih
	hh
	imp_output
	prt_odbg
	imp_input

history:

	Coded 1/12/76 by JC McMillan to facilitate testing ACC imp-interface
*/

#ifdef IMPPRTDEBUG

char *prt_ops [] {"nop","rts","str","cls","all","gvb","ret","inr"
		 ,"ins","eco","erp","err","rst","rrp","???" };

char *prt_types[] {
	 "Reglr","ErLdr","GoDwn","UnCtl","No-Op","RfNM ","DHost","D Imp"
	,"ErDat","IncMs","Reset","RefTA","RefWt","RefST","Ready","?"};

prt_dbg(str, cnt, typ, adr)
char *str, *adr;
int   cnt,typ;
{	register int count, bytex, newlin;
	char *address;		/* holds init value of adr */

	if (typ < 0)	/* if typ<0, msg MUST be printed */
	{	typ = -typ;
		printf("\nIMP ");
	} else {		/* handle optional msgs */
		if (!impdebug) return;
		printf("\n");
	}

	printf("%s:", str);
	if (!cnt) goto prtcrlf;
	if (cnt<0) cnt=512;

	cnt++;
	newlin = count = 0;
	address = adr;
	while (--cnt)
	{	bytex = *adr & 0377;
		printf(" %o", bytex);
		if (typ==2 && !count--)
		{	printf("=%s"
				,prt_ops [ bytex = (bytex>=0 && bytex<14 )
					? bytex:14]
				);
			count = (bytex==14 ? -1 : hhsize[bytex]-1);
		}
		if (((newlin++ & 017)==017) && (cnt!=1)) printf("\n   +");
		adr++;
	}
	if (typ == 3)
		printf("<%s", prt_types [*address&017] );
    prtcrlf:
	printf("\n");
}
#endif
/*name:
	flushimp

function:
	increment number of imp flushes and reload imp interface with
	buffer to dump data into

algorithm:
	set impi_flush flag
	handle statistics
	reload imp interface with black hole

parameters:
	none

returns:
	nothing

globals:
	impi_flush=
	imp_stat.i_flushes=

calls:
	impread			to load imp interface with address of hole

called by:
	imp_input
	ihbget
	hh

history:

	initial coding 1/7/75 by Steve Holmgren
	Modified jan/77 by JC McMillan to imbed debug-aid for ACC intrfc
*/

flushimp()
{		/* repeatedly called when we want imp interface cleaned out */
	impi_flush = 1;

	imp_stat.i_flushes++;
	impread( rathole,net_b_size );
}

/*name:
	ihbget

function:
	To reload the imp interface with a buffer to store data into

algorithm:
	If a buffer is available set impi_msg to address
		call impread to reload imp interface registers
	else
		couldnt get a buffer start flushing data

parameters:
	none

returns:
	nothing

globals:
	impi_msg=

calls:
	appendb			to add another buffer to impi_msg
	impread			to load imp interface registers
	flushimp		to flush imp data if couldnt get buffer
	printf	(sys)

called by:
	imp_input
	hh

history:

	initial coding 1/7/75 by Steve Holmgren
*/

ihbget()	/* stands for imp host buffer getter */
{
	register struct netbuf *bp;
	/* called when there is data to buffer from the imp */
	/* appendb returns 0 if cant get buffer */
	
	if( bp=appendb( impi_msg ) )
	{
		impi_msg = bp;
#ifndef BUFMOD
		impread( bp->b_data, net_b_size);
#endif BUFMOD
#ifdef BUFMOD
		impread( bp->b_loc, 0, net_b_size);
#endif BUFMOD
	}
	else
	{
		printf("\nIMP:Flush(No Bfrs)\n");
		flushimp();
	}
	
}

/*name:
	hh1

function:
	To search through host to host protocol messages strip out any
	that apply to the user ( allocates for now )

algorithm:
	Looks through each buffer of the message on host to host
	protocol boundaries for and allocate protocol msg. When
	one is found, copies the msg into hhmsg and overwrites
	with host to host nops. Calls allocate with the allocate
	protocol command with deals with it at the user level.
	once all the msg has been passed through, it as well as
	the imp to host leader is passed to the ncpdaemon for further
	processing.

parameters:
	none

returns:
	nothing

globals:
	impi_msg
	impi_mlen
	hhsize[]
	imp.nrcv

calls:
	allocate		to deal with allocate commands rcvd from net
	to_ncp			to send uninteresting protocol to ncpdaemon
	prt_dbg			to note all flush calls if in debug mode
	bytesout
	catmsg
	imphostlink
	vectomsg

called by:
	hh

history:

	initial coding 1/7/75 by Steve Holmgren
	modified 1/1/77 by Steve Holmgren to simplify and correct bug
	related to hh protocal crossing buffer boundary
	changed to_ncp arg jsq bbn 12-6-78
*/

hh1()
{

	register int hhcom;
	register char *sktp;
	register cnt;
	static char *daemsg, hhproto [96];

	daemsg = 0;
	while( impi_mlen > 0  ) {	/* while things in msg */
#ifndef BUFMOD
		hhcom = (impi_msg->b_qlink)->b_data[0] & 0377;
#endif BUFMOD
#ifdef BUFMOD
		hhcom = fbbyte(impi_msg->b_qlink->b_loc, 0);
#endif BUFMOD
		if( hhcom > NUMHHOPS ) {
			daemsg = catmsg( daemsg,impi_msg );
			goto fordaemon;
		}

		cnt = hhsize[ hhcom ];	/* get bytes in this command */
		impi_mlen =- cnt;	/* decrement impi_mlen */

		if( bytesout( &impi_msg,&hhproto,cnt,1 ))	/* msg not long enough */
			impi_mlen = 0;			/* force msg empty */
		else
		if( hhcom == hhall && (sktp=imphostlink( hhproto[1]|0200 )) ) {
			allocate( sktp,&hhproto );
			continue;
		}
		else
		if( hhcom == hhins && (sktp=imphostlink( hhproto[1]&0177 )) ) {
			if( (sktp->r_rdproc) &&
			    ((sktp -> r_rdproc) -> p_stat) ) { /* there ? */
#ifdef MSG
				sktp->INS_cnt =+ 1;     /* increment count */
				if (sktp->itab_p) awake(sktp->itab_p, 0);  /* awake awaiting process */
#endif MSG
				psignal( sktp->r_rdproc,SIGINR );
			}
			continue;
		}
		else
		if( hhcom == hhinr && (sktp=imphostlink( hhproto[1]|0200 )) ) {
			if( (sktp->r_rdproc) &&
			    ((sktp -> r_rdproc) -> p_stat) ) {
#ifdef MSG
				sktp->INR_cnt =+ 1;     /* increment count */
				if (sktp->itab_p) awake(sktp->itab_p, 0);  /* awake awaiting process */
#endif MSG
				psignal (sktp -> w_wrtproc, SIGINR);
			}
			continue;
		}
		else
		if( hhcom == hhnop )
			continue;

		vectomsg( &hhproto,cnt,&daemsg,1 );	/* got here then give it to daemon */
	}

	if( daemsg != 0 )		/* something in msg */
fordaemon:
		to_ncp (&imp.nrcv, 5, daemsg);  /* send to daemon */
}

/*name:
	allocate
function:
	To look over host to host allocate protocol messages .
	determine whether they are going to ncpdaemon or user
	send off to ncpdaemon, inc appropriate user fields.

algorithm:
	if host_link in conn tab
		if socket flags say to ncpdaemon
			send to ncpdaemon with imp to host leader
		else
			update num of messages alocated
			update number of bits allocated
			tell user allocate came in
			let user run

parameters:
	allocp 		pointer to a host host allocate

returns:
	nothing

globals:
	imp.nrcv
	sktp->w_msgs=
	sktp->w_falloc=
	sktp->w_flags=

calls:
	vectomsg		to build a msg from vec passed to send to ncp daemon
	to_ncp			to ship the allocate off to the ncp daemon
	dpadd (sys)		to add two double precision words
	wakeup (sys)		to let the user run

called by:
	hh1

history:

	initial coding 1/7/75 by Steve Holmgren
	modified to awake "awaiting" processes 8/14/78 S.Y. Chiu
	changed to_ncp arg jsq bbn 12-6-78
*/

allocate( skt_ptr,allocp )
struct wrtskt *skt_ptr;
{

	/* called from hh1 when a hh allocate is received */
	register char *ap;
	register struct wrtskt *sktp;
	struct netbuf *msgp;
#ifndef MSG
	int *sitp;
#endif MSG

	sktp = skt_ptr;
	ap = allocp;
	msgp = 0;
	if (sktp->w_flags & n_toncp)
	{
		vectomsg( allocp,8,&msgp,1 );
		to_ncp( &imp.nrcv,5,msgp );
	}
	else
	{
		sktp->w_msgs =+ swab( ap->a_msgs );
		sktp->w_falloc[0] =+ swab(ap->a_bitshi);
		dpadd(sktp->w_falloc,swab(ap->a_bitslo));
		sktp->w_flags =| n_allocwt;
		wakeup( sktp );
		/* wake up "await" processes, if any */
#ifndef MSG
		sitp = sktp;
		if (sitp = *(--sitp)) awake(sitp,0);
#endif MSG
#ifdef MSG
		if (sktp->itab_p) awake(sktp->itab_p, 0);
#endif MSG
	}
	
}

/*name:
	rmovepad

function:
	To remove the padding attached to every host host protocol msg
	and standard message by the imp

algorithm:
	given a bytesize in number of bytes in that size, calculate
	the number of 8 bit bytes.
	set the message length to that size
	run through the message a buffer at a time subtracting
	the buffer length from the calculated size. eventually
	it will go negative, since the number of bytes calculated
	is less that the actual number of bytes in the msg
	subtract the number of pad bytes from the last buffer in
	the message to setthe number of actual number of data bytes
	then free any remaining buffers.
	set impi_msg to the new last buffer.

parameters:
	none

returns:
	nothing

globals:
	impi_mlen=
	impi_msg=
	impi_msg->b_qlink

calls:
	swab (sys)		to switch top and bottom bytes
	freebuf			to release the last buffer from the message

called by:
	hh

history:

	initial coding 1/7/75 by Steve Holmgren
	added bytesizes multiple of 8 01/27/78 S. F. Holmgren
	modified so that impi_mlen is correctly set 8/11/78 S.Y. Chiu
*/

rmovepad()
{
	/*  calculates number of bytes from impleader then runs through impsg buffers
	    adding up counts until number calculated or end of msg is reached.
	    sets impcnt tothe min of amt in msg and calculated and discards
	    any excess bytes  */

	register struct netbuf *bfrp;
	register cnt;

	impi_mlen = swab( imp.bcnt );		/* get # bytesize bytes */
	impi_mlen = cnt = (impi_mlen * imp.bsize)/8;        /* turn into 8-bit bytes */

	impi_msg = bfrp = impi_msg->b_qlink;	/* pt at first bfr in msg */
	while(((cnt =- (bfrp->b_len & 0377)) > 0 )	/*get to last bfr with valid data */
		&& (bfrp->b_qlink != impi_msg))	/* protect against wrapping around -- JC McMillan */
	    bfrp = bfrp->b_qlink;

	if (cnt>0)	/* jcm -- note errors */
	{	printf(" \nIMP:Missing %d B\n", cnt);
		impi_mlen =- (( cnt*8 ) / impi_sockt->r_bsize );
	}

	if (cnt < 0)			/* cnt has -(# bytes to discard) */
		bfrp->b_len = (bfrp->b_len & 0377) + cnt;	/* discard extra bytes this buffer */
	while( bfrp->b_qlink != impi_msg )	/* while not pting at 1st bfr */
		freebuf(bfrp);
	impi_msg = bfrp;				/* set new handle on msg */
}

/*name:
	imphostlink

function:
	Checks to see if the current host and link are in the connection
	table (conn tab). Checks to see if the socket is open, if so
	returns a pointer to the socket. If not in conn tab or socket
	not open returns zero

algorithm:
	if host link in conn tab
		if skt open
			return socket ptr

	return zero

parameters:
	link			link to be checked with current host

returns:
	zero 			if not in conn tab or socket not open
	socket ptr		if in conn tab and socket open

globals:
	imp.host
	sktp->r_flags

calls:
	incontab		to see if host link is in conn tab

called by:
	hh1
	imp_input
	siguser

history:

	initial coding 1/7/75 by Steve Holmgren
*/

imphostlink( link )
char link;
{
	register sktp;
	if( sktp = incontab( (link & 0377), 0 ))
	{
		sktp = sktp->c_siptr;		/* contab returns ptr to entry
						   must get skt pointer
						*/
			return( sktp );
	}
	return( 0 );
}

/*name:
	imp_dwn

function:
	clean up ncp data structures so that an ncpdaemon restart will
	work correctly.

algorithm:
	reset the imp interface
	free any input message
	clean up input variables
	clear out all messages queued for the output side
	reset any rfnm bits
	let the kernel buffer code clean up its own

parameters:
	none

returns:
	nothing

globals:
	impi_msg =
	impi_mlen =
	impi_sockt =
	impi_con
	impi_flush =
	impotab (forward and backward links)
	host_map[-] =

calls:
	freemsg
	ncp_bfrdwn
	imp_reset
	printf
	host_clean

called by:
	imp_open

history:
	initial coding 6/22/76 by S. F. Holmgren
	modified 4/1/77, S.M. Abraham to fix bug in loop that frees
	all msgs in output queue. It wasn't resetting the msg ptr
	to the next msg in the queue.
	printf changed to 'NCP' from 'IMP' 31AUG77 JSK
	long host mods jsq bbn 1-30-79
	clear impi_con jsq BBN 3-21-79
*/
imp_dwn()
{
	register char *p;
	register int *q;

	/* reset the imp interface */
	imp_reset();		/* JSK */

	/* cleanup the input side */
	freemsg( impi_msg );
	impi_msg = impi_mlen = impi_sockt = impi_con = impi_flush =  0;

	/* clean up the output side */
	impotab.d_active = 0;
	/* get rid of messages waiting to be output */
#ifndef BUFMOD
	p = impotab.d_actf;
	while (p)
	{
		if( p->b_flags & B_SPEC )	/* this a net message */
			freemsg( p->b_dev );	/* free it */
		else
			iodone( p );		/* sys buffer say done */
		p = p -> b_forw;		/* pt to next msg */
	}
#endif BUFMOD
#ifdef BUFMOD
	freemsg(impotab.d_actf);
#endif BUFMOD
	impotab.d_actf = impotab.d_actl = 0;

#ifdef NCP
	/* clear out any waiting rfnm bits */
	host_clean(&host_map);
#endif NCP

	printf("\nNCP:Down!\n");	/*JCM & JSK*/

	/* let the net message software clean up */
	ncp_bfrdwn();
}
