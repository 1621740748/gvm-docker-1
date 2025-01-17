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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108797");
  script_version("2021-07-29T11:00:55+0000");
  script_tag(name:"last_modification", value:"2021-07-29 11:00:55 +0000 (Thu, 29 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-09 16:19:00 +0000 (Thu, 09 Jan 2020)");

  script_cve_id("CVE-2019-5304");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Improper Authentication Vulnerability in Some Huawei CloudEngine Products (huawei-sa-20190918-01-authentication)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an improper authentication vulnerability in some Huawei CloudEngine products.");

  script_tag(name:"insight", value:"There is an improper authentication vulnerability in some Huawei CloudEngine products. Due to the improper implementation of authentication for the serial port, an attacker could exploit this vulnerability by connecting to the affected products and run a series of commands. (Vulnerability ID: HWPSIRT-2019-06031)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2019-5304.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by connecting to the affected products and run a series of commands.");

  script_tag(name:"affected", value:"CloudEngine 12800 versions V200R003C00SPC810 V200R005C00SPC600 V200R005C00SPC800PWE V200R005C10");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190918-01-authentication-en");

  exit(0);
}

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
