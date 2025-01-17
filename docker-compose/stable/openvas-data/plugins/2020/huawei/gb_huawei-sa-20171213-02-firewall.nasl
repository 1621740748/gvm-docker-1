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
  script_oid("1.3.6.1.4.1.25623.1.0.143991");
  script_version("2020-11-12T10:19:31+0000");
  script_tag(name:"last_modification", value:"2020-11-12 10:19:31 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-05-27 08:29:16 +0000 (Wed, 27 May 2020)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2017-17162");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Products Memory Leak Vulnerability (huawei-sa-20171213-02-firewall)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Multiple Huawei firewalls are prone to a memory leak vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Some Huawei FireWall products have a memory leak vulnerability due to
  memory not being released when a local authenticated attacker executes special commands many times. An
  attacker could exploit it to cause memory leak, which may further lead to system exceptions.");

  script_tag(name:"impact", value:"An attacker could exploit it to cause memory leak, which may further lead
  to system exceptions.");

  script_tag(name:"affected", value:"Huawei Secospace USG6600 and USG9500.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171213-02-firewall-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:huawei:usg6600_firmware",
                     "cpe:/o:huawei:usg9500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = toupper(infos["version"]);

patch = get_kb_item("huawei/vrp/patch");

if (version == "V500R001C30SPC100" || version == "V500R001C30SPC200" || version == "V500R001C30SPC300") {
  report = report_fixed_ver(installed_version: version, installed_patch: patch,
                            fixed_version: "V500R001C30SPC600 / V500R001C60SPC300",
                            fixed_patch: "V500R001SPH012");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
