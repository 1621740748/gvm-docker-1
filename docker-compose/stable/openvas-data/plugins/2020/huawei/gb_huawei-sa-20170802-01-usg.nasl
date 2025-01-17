# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/o:huawei:usg6300_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143951");
  script_version("2020-08-31T09:40:59+0000");
  script_tag(name:"last_modification", value:"2020-08-31 09:40:59 +0000 (Mon, 31 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-05-20 08:29:59 +0000 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-8174");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Weak Algorithm Vulnerability in Huawei USG product (huawei-sa-20170802-01-usg)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a weak algorithm vulnerability in Huawei USG(USG6300/USG6600) products.");

  script_tag(name:"insight", value:"There is a weak algorithm vulnerability in Huawei USG(USG6300/USG6600) products. Attackers may exploit the weak algorithm vulnerability to crack the cipher text and cause confidential information leaks on the transmission links. (Vulnerability ID: HWPSIRT-2017-02028)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-8174.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Attackers may exploit this vulnerability to crack the cipher text and cause confidential information leaks on the transmission links.");

  script_tag(name:"affected", value:"IPS Module versions V100R001C30SPC600

NGFW Module versions V100R001C30SPC600

Secospace USG6300 versions V100R001C30SPC300

Secospace USG6600 versions V100R001C30SPC500 V100R001C30SPC600 V100R001C30SPC700 V100R001C30SPC800");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170802-01-usg-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (version =~ "^V100R001C30SPC300") {
  report = report_fixed_ver(installed_version: version, fixed_version: "V100R001C30SPC900");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
