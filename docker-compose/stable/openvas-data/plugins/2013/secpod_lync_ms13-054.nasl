# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902982");
  script_version("2021-08-05T12:20:54+0000");
  script_cve_id("CVE-2013-3129");
  script_bugtraq_id(60978);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-06 10:23:56 +0000 (Fri, 06 Aug 2021)");
  script_tag(name:"creation_date", value:"2013-07-10 13:08:01 +0530 (Wed, 10 Jul 2013)");
  script_name("Microsoft Lync Remote Code Execution Vulnerability (2848295)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2843160");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2768004");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028750");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-054");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_lync_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Ver", "MS/Lync/path");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code as
  the logged-on user.");

  script_tag(name:"affected", value:"- Microsoft Lync 2010

  - Microsoft Lync 2013");

  script_tag(name:"insight", value:"The flaw is due to an error when processing TrueType fonts and can be
  exploited to cause a buffer overflow via a specially crafted file.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-054.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(get_kb_item("MS/Lync/Ver"))
{
  path = get_kb_item("MS/Lync/path");
  if(path)
  {
    commVer = fetch_file_version(sysPath:path, file_name:"Rtmpltfm.dll");
    if(commVer)
    {
      if(version_in_range(version:commVer, test_version:"5.0", test_version2:"5.0.8308.199") ||
         version_in_range(version:commVer, test_version:"4.0", test_version2:"4.0.7577.4391"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
