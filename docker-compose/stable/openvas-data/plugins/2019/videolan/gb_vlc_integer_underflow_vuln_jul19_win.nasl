# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815253");
  script_version("2020-10-27T15:01:28+0000");
  script_cve_id("CVE-2019-13602");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)");
  script_tag(name:"creation_date", value:"2019-07-19 08:39:01 +0530 (Fri, 19 Jul 2019)");

  script_name("VLC Media Player Integer Underflow Vulnerability July19 (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");

  script_xref(name:"URL", value:"https://www.videolan.org/security/sb-vlc308.html");
  script_xref(name:"URL", value:"https://git.videolan.org/?p=vlc.git;a=commit;h=8e8e0d72447f8378244f5b4a3dcde036dbeb1491");
  script_xref(name:"URL", value:"https://git.videolan.org/?p=vlc.git;a=commit;h=b2b157076d9e94df34502dd8df0787deb940e938");

  script_tag(name:"summary", value:"VLC media player is prone to an integer underflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an integer underflow issue in MP4_EIA608_Convert().");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  crash the application and launch further attacks using specially crafted files.");

  script_tag(name:"affected", value:"VideoLAN VLC media player prior to 3.0.8 on Windows.");

  script_tag(name:"solution", value:"Update to version 3.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

ver = infos["version"];
path = infos["location"];

if(version_is_less(version:ver, test_version:"3.0.8")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"3.0.8", install_path: path);
  security_message(data:report);
  exit(0);
}

exit(99);
