###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_easy_youtube_gallery_sql_injection_vuln.nasl 57768 2016-05-24 13:11:01 +0530 May$
#
# Joomla Easy Youtube Gallery SQL Injection Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808059");
  script_version("2020-05-08T08:34:44+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2016-05-24 13:11:01 +0530 (Tue, 24 May 2016)");

  script_name("Joomla Easy Youtube Gallery SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Joomla component
  Easy Youtube Gallery and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient
  validation of user supplied input via 'mycategory' parameter to
  'index.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla Easy Youtube Gallery 1.0.2");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39590/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_easy_youtube_gallery&view=videos&mycategory"
          + "=SQL-INJECTION-TEST'&defaultvideo=9&Itemid=752";

if(http_vuln_check(port:http_port, url:url, check_header:FALSE, pattern:"You have an error in your SQL syntax",
                   extra_check:"SQL-INJECTION-TEST")) {
  report = http_report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);
