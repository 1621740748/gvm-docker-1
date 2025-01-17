###############################################################################
# OpenVAS Vulnerability Test
#
# Moxa MXview Private Key Disclosure
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:moxa:mxview';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140245");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2017-7455", "CVE-2017-7456");
  script_version("2020-05-08T08:34:44+0000");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2017-04-11 13:15:09 +0200 (Tue, 11 Apr 2017)");
  script_name("Moxa MXview Private Key Disclosure");

  script_tag(name:"summary", value:"MXview stores a copy of its web servers private key under C:\Users\TARGET-USER\AppData\Roaming\moxa\mxview\web\certs\mxview.key.
Remote attackers can easily access/read this private key `mxview.key` file by making an HTTP GET request.");
  script_tag(name:"vuldetect", value:"Try to read `/certs/mxview.key`");
  script_tag(name:"affected", value:"Moxa MXview V2.8");
  script_tag(name:"solution", value:"Vendor has released a fix.");
  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_moxa_mxview_web_detect.nasl");
  script_require_ports("Services/www", 80, 81);
  script_mandatory_keys("moxa/mxviev/installed");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

url = '/certs/mxview.key';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "BEGIN PRIVATE KEY" >< buf && "END PRIVATE KEY" >< buf )
{
  report = 'It was possible to read the private key by requesting ' + http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n\nResponse:\n\n' + buf;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
