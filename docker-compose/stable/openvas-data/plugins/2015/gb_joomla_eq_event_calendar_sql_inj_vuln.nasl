###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_eq_event_calendar_sql_inj_vuln.nasl 50151 2015-06-23 16:57:59Z june$
#
# Joomla! EQ Event Calendar component SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805801");
  script_version("2020-05-08T08:34:44+0000");
  script_cve_id("CVE-2015-4654");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)");
  script_tag(name:"creation_date", value:"2015-06-23 16:59:30 +0530 (Tue, 23 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Joomla! EQ Event Calendar component SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Joomla EQ
  Event Calendar component and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to joomla component EQ
  Event Calendar is not filtering data in 'id' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla! component EQ Event Calendar");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.scip.ch/en/?vuldb.76002");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132220");
  script_xref(name:"URL", value:"http://vulndb.blogspot.in/2015/06/eq-event-calendar-on-joomla-id-sql.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

foreach path (make_list("/component", "/en/component"))
{
  url = dir + "/index.php" + path + "/eqfullevent?view=lists&"
            + "id=1%27SQL-INJECTION-TEST";

  if(http_vuln_check(port:http_port, url:url, pattern:"SQL-INJECTION-TEST",
                     extra_check:"You have an error in your SQL syntax"))
  {
    report = http_report_vuln_url(port: http_port, url: url);
    security_message(port: http_port, data: report);
    exit(0);
  }
}

exit(99);
