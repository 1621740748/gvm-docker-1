###############################################################################
# OpenVAS Vulnerability Test
#
# phpMyAdmin Multiple XSS Vulnerabilities -01 May16 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807595");
  script_version("2020-11-19T14:17:11+0000");
  script_cve_id("CVE-2016-2561");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-11-19 14:17:11 +0000 (Thu, 19 Nov 2020)");
  script_tag(name:"creation_date", value:"2016-05-17 12:12:08 +0530 (Tue, 17 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("phpMyAdmin Multiple XSS Vulnerabilities -01 May16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin
  and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input validation error via table/column name in database normalization
    page.

  - An input validation error in 'templates/database/structure/sortable_header.phtml'
    script in the database structure page.

  - An input validation error in 'db_central_columns.php' script in the
    central columns page.

  - An input validation error in 'normalization.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via crafted parameters.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.4.x before 4.4.15.5
  and 4.5.x before 4.5.5.1 on Linux.");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.4.15.5 or
  4.5.5.1 or later or apply the patch from the linked references.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-12");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!phpPort = get_app_port(cpe:CPE)) exit(0);

if(!phpVer = get_app_version(cpe:CPE, port:phpPort)) exit(0);

if(phpVer =~ "^(4\.5)")
{
  if(version_is_less(version:phpVer, test_version:"4.5.5.1"))
  {
    fix = "4.5.5.1";
    VULN = TRUE;
  }
}

else if(phpVer =~ "^(4\.4)")
{
  if(version_is_less(version:phpVer, test_version:"4.4.15.5"))
  {
    fix = "4.4.15.5";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(port:phpPort, data:report);
  exit(0);
}

