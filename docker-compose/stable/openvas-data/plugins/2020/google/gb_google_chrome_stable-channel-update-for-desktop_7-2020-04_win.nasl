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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816737");
  script_version("2020-10-29T15:35:19+0000");
  script_cve_id("CVE-2020-6454", "CVE-2020-6423", "CVE-2020-6455", "CVE-2020-6430",
                "CVE-2020-6456", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433",
                "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437",
                "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441",
                "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445",
                "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-04-08 11:59:56 +0530 (Wed, 08 Apr 2020)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_7-2020-04)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - A use after free issue in extensions.

  - A use after free issue in audio.

  - An out of bounds read issue in WebSQL.

  - A type confusion issue in V8.

  - A use after free in devtools.

  - A use after free in window management.

  - A use after free in V8.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, gain access to sensitive data, bypass security
  restrictions, and launch denial of service attacks.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 81.0.4044.92 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  81.0.4044.92 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/04/stable-channel-update-for-desktop_7.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"81.0.4044.92"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"81.0.4044.92", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
