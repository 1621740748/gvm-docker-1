###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL Multiple Vulnerabilities - Mar17 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809897");
  script_version("2020-10-19T15:33:20+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-03-07 16:43:29 +0530 (Tue, 07 Mar 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("PostgreSQL Multiple Vulnerabilities - Mar17 (Windows)");

  script_tag(name:"summary", value:"This host is running PostgreSQL and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to escalate privileges and to cause denial of service
  conditions, also can lead to data corruption.");

  script_tag(name:"affected", value:"PostgreSQL version 9.2.x before 9.2.20,
  9.3.x before 9.3.16, 9.4.x before 9.4.11, and 9.5.x before 9.5.6 and 9.6.x
  before 9.6.2.");

  script_tag(name:"solution", value:"Upgrade to version 9.2.20 or 9.3.16 or
  9.4.11 or 9.5.6 or 9.6.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1733");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-5-6.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/current/static/release-9-4-11.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
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

if(vers =~ "^9\.2") {
  if(version_is_less(version:vers, test_version:"9.2.20")) {
    fix = "9.2.20";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.3") {
  if(version_is_less(version:vers, test_version:"9.3.16")) {
    fix = "9.3.16";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.4") {
  if(version_is_less(version:vers, test_version:"9.4.11")) {
    fix = "9.4.11";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.5") {
  if(version_is_less(version:vers, test_version:"9.5.6")) {
    fix = "9.5.6";
    VULN = TRUE;
  }
}

else if(vers =~ "^9\.6") {
  if(version_is_less(version:vers, test_version:"9.6.2")) {
    fix = "9.6.2";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
