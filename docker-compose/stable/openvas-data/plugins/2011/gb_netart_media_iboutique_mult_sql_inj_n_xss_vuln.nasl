##############################################################################
# OpenVAS Vulnerability Test
#
# NetArt Media iBoutique 'page' SQL Injection and XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802404");
  script_version("2020-08-24T15:18:35+0000");
  script_cve_id("CVE-2010-5020");
  script_bugtraq_id(41014);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-11-14 13:46:57 +0530 (Mon, 14 Nov 2011)");
  script_name("NetArt Media iBoutique 'page' SQL Injection and XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6444");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31871");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13945/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running NetArt Media iBoutique and is prone to
  multiple SQL injection and cross-site scripting vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws are due to an,

  - Input passed to the 'cat' and 'key'  parameter in index.php (when 'mod'
  is set to 'products') is not properly sanitised before being used in a SQL query.

  - Input passed to the 'page' parameter in index.php is not properly sanitised
  before being used in a SQL query.

  This can further be exploited to conduct cross-site scripting attacks
  via SQL error messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct SQL
  injection and cross-site scripting attacks.");

  script_tag(name:"affected", value:"NetArt Media iBoutique version 4.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

ibPort = http_get_port(default:80);

if(!http_can_host_php(port:ibPort)){
  exit(0);
}

foreach dir (make_list_unique("/iboutique", http_cgi_dirs(port:ibPort)))
{

  if(dir == "/") dir = "";

  ##Request to confirm application
  rcvRes = http_get_cache(item: dir + "/index.php", port:ibPort);

  if(">Why iBoutique?</" >< rcvRes)
  {
    url = string(dir, "/index.php?page='");

    if(http_vuln_check(port:ibPort, url:url, pattern:"You have an error" +
                      " in your SQL syntax;", check_header: TRUE))
    {
      security_message(port:ibPort);
      exit(0);
    }
  }
}

exit(99);
