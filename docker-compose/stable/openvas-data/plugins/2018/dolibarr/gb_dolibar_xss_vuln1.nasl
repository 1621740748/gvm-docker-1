###############################################################################
# OpenVAS Vulnerability Test
#
# Dolibarr < 7.0.1 XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:dolibarr:dolibarr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140652");
  script_version("2021-06-30T11:00:43+0000");
  script_tag(name:"last_modification", value:"2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-04 13:51:40 +0700 (Thu, 04 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-16 15:24:00 +0000 (Tue, 16 Jan 2018)");

  script_cve_id("CVE-2017-17971");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dolibarr < 7.0.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("dolibarr/detected");

  script_tag(name:"summary", value:"Dolibarr ERP/CRM is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The test_sql_and_script_inject function in htdocs/main.inc.php in Dolibarr
ERP/CRM blocks some event attributes but neither onclick nor onscroll, which allows XSS.");

  script_tag(name:"affected", value:"Dolibarr ERP/CRM version 6.0.4 and prior.");

  script_tag(name:"solution", value:"Update to version 7.0.1 or later.");

  script_xref(name:"URL", value:"https://github.com/Dolibarr/dolibarr/issues/8000");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
