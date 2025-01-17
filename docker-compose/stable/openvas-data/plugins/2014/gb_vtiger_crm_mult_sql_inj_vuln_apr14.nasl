# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:vtiger:vtiger_crm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804542");
  script_version("2021-05-27T13:59:44+0000");
  script_cve_id("CVE-2013-3213");
  script_bugtraq_id(61563);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-27 13:59:44 +0000 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2014-04-17 18:28:20 +0530 (Thu, 17 Apr 2014)");

  script_name("Vtiger CRM Multiple SQLi Vulnerabilities (April 14)");

  script_tag(name:"summary", value:"Vtiger CRM is prone to multiple SQL injection (SQLi)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - input passed via multiple parameters to various SOAP methods is not properly sanitised before
  being used in an SQL query.

  - an error within the 'validateSession()' function and multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code, bypass certain security restrictions, manipulate certain data, and
  compromise a vulnerable system.");

  script_tag(name:"affected", value:"Vtiger CRM version 5.0.0 through 5.4.0.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"https://www.vtiger.com/products/crm/540/VtigerCRM540_Security_Patch.zip");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54336");
  script_xref(name:"URL", value:"https://www.vtiger.com/blogs/?p=1467");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27279");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"5.0.0", test_version2:"5.4.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See the referenced advisory");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);