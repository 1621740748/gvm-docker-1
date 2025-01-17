# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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

CPE = "cpe:/a:hp:onboard_administrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803767");
  script_version("2020-04-28T08:39:12+0000");
  script_tag(name:"last_modification", value:"2020-04-28 08:39:12 +0000 (Tue, 28 Apr 2020)");
  script_tag(name:"creation_date", value:"2013-10-03 17:49:51 +0530 (Thu, 03 Oct 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"cvss_base", value:"6.4");

  script_cve_id("CVE-2011-3155");
  script_bugtraq_id(50053);

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Onboard Administrator Security Bypass Vulnerability");

  script_tag(name:"summary", value:"HP Onboard Administrator is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to HP Onboard Administrator 3.32 or later.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error.");

  script_tag(name:"affected", value:"HP Onboard Administrator (OA) versions 3.21 through 3.31.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass intended access
  restrictions via unknown vectors.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46385");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03048779");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_onboard_administrator_detect.nasl");
  script_mandatory_keys("hp/onboard_administrator/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.21", test_version2: "3.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.32");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
