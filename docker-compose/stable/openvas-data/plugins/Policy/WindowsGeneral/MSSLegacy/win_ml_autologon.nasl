# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109313");
  script_version("2021-02-08T08:10:47+0000");
  script_tag(name:"last_modification", value:"2021-02-08 08:10:47 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"creation_date", value:"2018-06-15 12:04:43 +0200 (Fri, 15 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: MSS: (AutoAdminLogon) Enable Automatic Logon");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1");

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.4.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.4.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 4.3 Ensure the Use of Dedicated Administrative Accounts");

  script_tag(name:"summary", value:"This test checks the setting for policy 'MSS: (AutoAdminLogon)
Enable Automatic Logon (not recommended)' on Windows hosts (at least Windows 7).");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)";
solution = "Set following UI path accordingly: Computer Configuration/Administrative Templates/MSS (Legacy)/" + title;
type = "HKLM";
key = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
item = "AutoAdminLogon";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_reg_sz(key:key, item:item, type:type, default:default, partial:FALSE,
    multi_sz:FALSE);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
