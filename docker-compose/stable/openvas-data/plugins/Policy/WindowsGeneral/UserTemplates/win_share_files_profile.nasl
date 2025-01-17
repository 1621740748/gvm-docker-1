# Copyright (C) 2018 Greenbone Networks GmbH
#
# Text descriptions excerpted from a referenced source are
# Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.109524");
  script_version("2021-02-12T08:55:58+0000");
  script_tag(name:"last_modification", value:"2021-02-12 08:55:58 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2018-06-28 16:36:16 +0200 (Thu, 28 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Prevent users from sharing files within their profile");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"1;0");

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 19.7.27.1 (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 19.7.26.1 (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 14.6 Protect Information through Access Control Lists");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting specifies whether users can share files
within their profile. By default users are allowed to share files within their profile to other
users on their network after an administrator opts in the computer.

An administrator can opt in the computer by using the sharing wizard to share a file within their
profile.

If you enable this policy setting, users cannot share files within their profile using the sharing
wizard.

Also, the sharing wizard cannot create a share at %root%\users and can only be used to create SMB
shares on folders.

If you disable or don't configure this policy setting, users can share files out of their user
profile after an administrator has opted in the computer.

(C) Microsoft Corporation 2015.");

  exit(0);
}


include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Prevent users from sharing files within their profile";
solution = "Set following UI path accordingly:
User Configuration/Administrative Templates/Windows Components/Network Sharing/" + title;
type = "HKU";
item = "NoInplaceSharing";
key = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
reg_path = type + "\[SID]\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else if(!sids = registry_hku_subkeys())
  results = policy_report_empty_hku();
else
  results = policy_match_exact_dword_profiles(key:key, item:item, default:default, sids:sids);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);