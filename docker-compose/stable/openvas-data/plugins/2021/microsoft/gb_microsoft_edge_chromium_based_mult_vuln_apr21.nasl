# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817708");
  script_version("2021-04-20T03:57:33+0000");
  script_cve_id("CVE-2021-21194", "CVE-2021-21195", "CVE-2021-21196", "CVE-2021-21197",
                "CVE-2021-21198", "CVE-2021-21199");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-20 03:57:33 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-15 11:24:37 +0530 (Thu, 15 Apr 2021)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - Apr21");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An use after free error in Aura.

  - An out of bounds read error in IPC.

  - Multiple heap buffer overflow errors in TabStrip.

  - An use after free error in V8.

  - An use after free error in screen capture.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to  execute arbitrary code, gain access to sensitive information, bypass
  security restrictions, cause denial of service and may have other impacts.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 89.0.4389.114.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21199");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"89.0.4389.114"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"89.0.4389.114", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
