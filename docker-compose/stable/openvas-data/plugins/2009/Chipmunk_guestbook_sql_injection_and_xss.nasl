###############################################################################
# OpenVAS Vulnerability Test
#
# Chipmunk Guestbook Index.PHP SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100039");
  script_version("2021-03-11T10:58:32+0000");
  script_tag(name:"last_modification", value:"2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
  script_bugtraq_id(18195);
  script_cve_id("CVE-2008-6368");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Chipmunk Guestbook Index.PHP SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Chipmunk Guestbook is prone to an SQL-injection vulnerability
  because it fails to properly sanitize user-supplied input before using it in an SQL query.");

  script_tag(name:"impact", value:"A successful exploit could allow an attacker to compromise the
  application, access or modify data, or exploit vulnerabilities in the underlying database.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18195");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/guestbook", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);
  if(!res || res !~ "Powered by.+>Chipmunk Guestbook<")
    continue;

  url = dir + "/index.php?start=<script>alert(document.cookie)</script>";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!buf)
    continue;

  if(buf =~ "^HTTP/1\.[01] 200" &&
     egrep(pattern:".*You have an error in your SQL syntax.*", string:buf) &&
     egrep(pattern:".*<script>alert\(document\.cookie\)</script>.*", string:buf) ) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
