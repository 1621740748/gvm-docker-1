# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800281");
  script_version("2021-05-18T07:55:59+0000");
  script_tag(name:"last_modification", value:"2021-05-18 07:55:59 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4539");
  script_bugtraq_id(36002);
  script_name("SQLiteManager <= 1.2.0 XSS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28642");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/36002");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sqlitemanager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sqlitemanager/detected");

  script_tag(name:"summary", value:"SQLiteManager is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"insight", value:"Input passed to the 'redirect' parameter in 'main.php' is not
  properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose sensitive
  information, or conduct XSS attacks.");

  script_tag(name:"affected", value:"SQLiteManager version 1.2.0 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

vers = get_kb_item("www/" + port + "/SQLiteManager");
if(!vers)
  exit(0);

vers = eregmatch(pattern:"^(.+) under (/.*)$", string:vers);

url = string(vers[2], "/main.php?redirect=<script>alert('Exploit-XSS')</script>");
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);
if(res =~ "^HTTP/1\.[01] 200" && "Exploit-XSS" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

if(vers[1] && version_is_less_equal(version:vers[1], test_version:"1.2.0")) {
  security_message(port:port);
  exit(0);
}

exit(99);