###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL 'make check' Local Privilege Escalation Vulnerability July14 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804711");
  script_version("2020-04-20T13:31:49+0000");
  script_cve_id("CVE-2014-0067");
  script_bugtraq_id(65721);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)");
  script_tag(name:"creation_date", value:"2014-07-07 15:34:21 +0530 (Mon, 07 Jul 2014)");
  script_name("PostgreSQL 'make check' Local Privilege Escalation Vulnerability July14 (Windows)");

  script_tag(name:"summary", value:"This host is installed with PostgreSQL and is prone to local privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an error when creating a PostgreSQL database cluster during
  'make check'.");

  script_tag(name:"impact", value:"Successful exploitation may allow local attacker to gain temporary server
  access and elevated privileges.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.3 and earlier");

  script_tag(name:"solution", value:"Update to version 9.3.6, 9.4.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57054");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91459");
  script_xref(name:"URL", value:"http://wiki.postgresql.org/wiki/20140220securityrelease");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "secpod_postgresql_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(vers !~ "^(8\.4|9\.[0-3])\.")
  exit(99);

if(version_in_range(version:vers, test_version:"8.4", test_version2:"9.3.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:loc);
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"8.4 - 9.3.3");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
