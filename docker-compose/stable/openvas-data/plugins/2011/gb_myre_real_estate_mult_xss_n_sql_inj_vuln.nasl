###############################################################################
# OpenVAS Vulnerability Test
#
# MYRE Real Estate Software Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802157");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_bugtraq_id(49540);
  script_cve_id("CVE-2011-3393", "CVE-2011-3394");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MYRE Real Estate Software Multiple XSS and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=346");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17811");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_MRS_SQL_XSS_Vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site and to cause SQL Injection attack to gain sensitive information.");

  script_tag(name:"affected", value:"MYRE Real Estate Software.");

  script_tag(name:"insight", value:"The flaws are due to input passed to the

  - 'page' parameter in findagent.php is not properly sanitized before being
  used in SQL queries.

  - 'country1', 'state1', and 'city1' parameters in findagent.php are not
  properly verified before it is returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running MYRE Real Estate Software and is prone to
  multiple cross site scripting and SQL injection vulnerabilities");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/realestate", "/", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);

  if('MYRE Real Estate Software' >< res) {
    url = string(dir, "/findagent.php?country1=<script>alert(/document.cookie/)</script>");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && '"><script>alert(/document.cookie/)</script>' >< res){
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }

    url = string(dir, "/findagent.php?page='");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(">You have an error in your SQL syntax;" >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
