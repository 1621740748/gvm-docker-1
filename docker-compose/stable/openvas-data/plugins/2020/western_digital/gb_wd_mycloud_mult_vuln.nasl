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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143397");
  script_version("2020-09-02T13:38:42+0000");
  script_tag(name:"last_modification", value:"2020-09-02 13:38:42 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 07:36:08 +0000 (Mon, 27 Jan 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2019-18929", "CVE-2019-18930", "CVE-2019-18931");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products < 2.40.155 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple Western Digital My Cloud products are prone to multiple vulnerabilities:

  - Multiple authenticated RCE via stack-based buffer overflows in download_mgr.cgi (CVE-2019-18929, CVE-2019-18930)

  - Buffer Overflow with Extended Instruction Pointer (EIP) control via crafted GET/POST parameters (CVE-2019-18931)");

  script_tag(name:"affected", value:"Western Digital My Cloud EX2 Ultra, Mirror Gen 2, EX4100, PR2100 and PR4100 with
  firmware versions prior to 2.40.155 are known to be affected. Other end-of-life products might be affected as well.");

  script_tag(name:"solution", value:"Update to firmware version 2.40.155 or later.

  Note: Some My Cloud products are already end-of-life and doesn't receive any updates anymore.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/productsecurity/wdc-20006-my-cloud-firmware-version-2-40-155");
  script_xref(name:"URL", value:"https://github.com/DelspoN/CVE/tree/master/CVE-2019-18929");
  script_xref(name:"URL", value:"https://github.com/DelspoN/CVE/tree/master/CVE-2019-18930");
  script_xref(name:"URL", value:"https://github.com/DelspoN/CVE/tree/master/CVE-2019-18931");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2_firmware",
                     "cpe:/o:wdc:my_cloud_ex4_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "2.40.155")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.40.155");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
