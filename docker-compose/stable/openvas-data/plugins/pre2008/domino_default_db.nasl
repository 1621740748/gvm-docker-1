###############################################################################
# OpenVAS Vulnerability Test
#
# Lotus Domino administration databases
#
# Authors:
# Javier Fernandez-Sanguino Pe�a <jfs@computer.org>
# based on the iis_samples.nasl script written by Renaud Deraison
# Script was modified by Jasmin Amidzic <jasminsabina@yahoo.com>.
#
# Copyright:
# Copyright (C) 2001 Javier Fern�ndez-Sanguino Pe�a
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10629");
  script_version("2020-09-22T09:01:10+0000");
  script_tag(name:"last_modification", value:"2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2000-0021", "CVE-2002-0664");
  script_bugtraq_id(5101, 881);

  script_name("Lotus Domino administration databases");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Javier Fern�ndez-Sanguino Pe�a");
  script_family("Web Servers");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.lotus.com/developers/devbase.nsf/articles/doc1999112200");

  script_tag(name:"solution", value:"Verify all the ACLs for these databases and remove those not needed.");

  script_tag(name:"summary", value:"This script determines if some default databases can be read remotely.

  An anonymous user can retrieve information from this Lotus Domino server: users, databases, configuration
  of servers (including operating system and hard disk partitioning), logs of access to users (which could
  expose sensitive data if GET html forms are used).

  This issues are discussed in the references 'Lotus White Paper: A Guide to Developing Secure Domino Applications' (december 1999).");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("host_details.inc");

function test_cgi( port, url, output ) {

  if( http_is_cgi_installed_ka( port:port, item:url ) ) {

    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( "Please identify yourself" >!< res &&
        'type="password"' >!< res &&
        "<TITLE>Server Login</TITLE>" >!< res &&
        res !~ ">Domino Administrator.*Help</" ) { # The homepage.nsf is just a default landing page these days...
      vuln_db += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + " Reason: This must be considered a security risk since " + output + ".";
      set_kb_item( name: "www/domino/" + port + "/db", value:url );
    } else {
      auth_db += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) ;
    }
  }
  return( 0 );
}

vuln_db = "";
auth_db = "";

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

urls = make_array( dir + "/catalog.nsf", "the list of databases in the server can be retrieved",
                   dir + "/cersvr.nsf", "the information on the server certificates can be read anonymously",
                   dir + "/domlog.nsf", "the logs of the domain servers  can be read anonymously",
                   dir + "/events4.nsf", "the list of events that have taken place can be read anonymously, this might lead to information disclosure of users and hidden databases",
                   dir + "/log.nsf", "the server log can be retrieved",
                   dir + "/names.nsf", "the users and groups in the server can be accessed anonymously, in some cases, access to the hashed passwords will be possible",
                   dir + "/setup.nsf", "the server might be configured remotely or the current setup might be downloaded",
                   dir + "/statrep.nsf", "the reports generated by administrators can be read anoymously",
                   dir + "/webadmin.nsf", "the server administration database can be read anonymously",
                   dir + "/zmevladm.nsf", "it provides arbitrary users with Manager level access, which allows the users to read or modify the import/export scripts" );

foreach url ( keys( urls ) ) {
  test_cgi( port:port, url:url, output:urls[url] );
}

# We should add more info here on the output: on how this database
# affects the server
foreach url( make_list( "/852566C90012664F", "/account.nsf", "/accounts.nsf",
                        "/admin4.nsf", "/admin5.nsf", "/admin.nsf",
                        "/a_domlog.nsf", "/agentrunner.nsf", "/AgentRunner.nsf",
                        "/alog.nsf", "/archive/a_domlog.nsf", "/archive/l_domlog.nsf",
                        "/bookmark.nsf", "/bookmarks.nsf", "/books.nsf",
                        "/busytime.nsf", "/calendar.nsf", "/certa.nsf",
                        "/certlog.nsf", "/certsrv.nsf", "/clbusy.nsf",
                        "/cldbdir.nsf", "/clusta4.nsf", "/collect4.nsf",
                        "/cpa.nsf", "/da.nsf", "/database.nsf", "/dba4.nsf",
                        "/dbdirman.nsf", "/db.nsf", "/dclf.nsf",
                        "/DEASAppDesign.nsf", "/DEASLog01.nsf", "/DEASLog02.nsf",
                        "/DEASLog03.nsf", "/DEASLog04.nsf", "/DEASLog05.nsf",
                        "/DEASLog.nsf", "/decsadm.nsf", "/decslog.nsf",
                        "/DEESAdmin.nsf", "/default.nsf", "/deslog.nsf",
                        "/dirassist.nsf", "/doc/dspug.nsf", "/doc/helpadmn.nsf",
                        "/doc/javapg.nsf", "/doc/readmec.nsf", "/doc/readmes.nsf",
                        "/doc/svrinst.nsf", "/doc/wksinst.nsf", "/doladmin.nsf",
                        "/domadmin.nsf", "/domcfg.nsf", "/domguide.nsf",
                        "/domino.nsf", "/dspug.nsf", "/event.nsf", "/events5.nsf",
                        "/events.nsf", "/group.nsf", "/groups.nsf", "/help4.nsf",
                        "/help/decsdoc.nsf", "/help/dols_help.nsf", "/help/help5_admin.nsf",
                        "/help/help5_client.nsf", "/help/help5_designer.nsf",
                        "/help/help6_admin.nsf", "/help/help6_client.nsf",
                        "/help/help6_designer.nsf", "/help/lccon.nsf", "/help/lsxlc.nsf",
                        "/helplt4.nsf", "/help/readme.nsf", "/hidden.nsf",
                        "/home.nsf", "/homepage.nsf", "/iNotes/Forms5.nsf",
                        "/iNotes/Forms5.nsf/$DefaultNav", "/jotter.nsf", "/lccon.nsf",
                        "/ldap.nsf", "/l_domlog.nsf", "/leiadm.nsf", "/leilog.nsf",
                        "/leivlt.nsf", "/lndfr.nsf", "/loga4.nsf", "/mab.nsf",
                        "/mail10.box", "/mail1.box", "/mail2.box", "/mail3.box",
                        "/mail4.box", "/mail5.box", "/mail6.box", "/mail7.box",
                        "/mail8.box", "/mail9.box", "/mail/admin.nsf", "/mail.box",
                        "/mailw46.nsf", "/msdwda.nsf", "/mtabtbls.nsf", "/mtatbls.nsf",
                        "/mtstore.nsf", "/nntp/nd000001.nsf", "/nntp/nd000002.nsf",
                        "/nntp/nd000003.nsf", "/nntppost.nsf", "/notes.nsf",
                        "/ntsync45.nsf", "/ntsync4.nsf", "/perweb.nsf",
                        "/private.nsf", "/products.nsf", "/proghelp/KBCCV11.NSF",
                        "/public.nsf", "/qpadmin.nsf", "/qstart.nsf",
                        "/quickplace/quickplace/main.nsf", "/quickstart/qstart50.nsf",
                        "/quickstart/wwsample.nsf", "/reports.nsf", "/sample/faqw46.nsf",
                        "/sample/framew46.nsf", "/sample/siregw46.nsf", "/schema50.nsf",
                        "/secret.nsf", "/secure.nsf", "/setupweb.nsf", "/smbcfg.nsf",
                        "/smconf.nsf", "/smency.nsf", "/smhelp.nsf", "/smmsg.nsf",
                        "/smquar.nsf", "/smsolar.nsf", "/smtime.nsf", "/smtp.box",
                        "/smtpibwq.nsf", "/smtp.nsf", "/smtpobwq.nsf", "/smtptbls.nsf",
                        "/smvlog.nsf", "/software.nsf", "/srvnam.htm", "/statmail.nsf",
                        "/stats675.nsf", "/stauths.nsf", "/stautht.nsf", "/stconfig.nsf",
                        "/stconf.nsf", "/stdnaset.nsf", "/stdomino.nsf", "/stlog.nsf",
                        "/streg.nsf", "/stsrc.nsf", "/user.nsf", "/userreg.nsf", "/users.nsf",
                        "/vpuserinfo.nsf", "/web.nsf", "/webstart.nsf", "/welcome.nsf" ) ) {

  test_cgi( port:port, url:dir + url, output:"this database can be read anonymously" );
}

if( vuln_db ) {
  security_message( port:port, data:'We found the following domino databases:\n' + vuln_db );
}

if( auth_db ) {
  log_message( port:port, data:'\nThe following databases exists but are password-protected:\n' + auth_db );
}

exit( 99 );
