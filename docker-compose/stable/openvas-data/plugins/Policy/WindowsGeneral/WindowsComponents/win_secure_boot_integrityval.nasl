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
  script_oid("1.3.6.1.4.1.25623.1.0.109388");
  script_version("2019-12-16T11:36:02+0000");
  script_tag(name:"last_modification", value:"2019-12-16 11:36:02 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"creation_date", value:"2018-06-26 08:26:52 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Allow Secure Boot for integrity validation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"1;0");

  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to configure whether Secure Boot
will be allowed as the platform integrity provider for BitLocker operating system drives.

Secure Boot ensures that the PC's pre-boot environment only loads firmware that is digitally signed
by authorized software publishers. Secure Boot also provides more flexibility for managing pre-boot
configuration than legacy BitLocker integrity checks.

If you enable or do not configure this policy setting, BitLocker will use Secure Boot for platform
integrity if the platform is capable of Secure Boot-based integrity validation.

If you disable this policy setting, BitLocker will use legacy platform integrity validation, even on
systems capable of Secure Boot-based integrity validation.

When this policy is enabled and the hardware is capable of using Secure Boot for BitLocker scenarios,
the 'Use enhanced Boot Configuration Data validation profile' group policy setting is ignored and
Secure Boot verifies BCD settings according to the Secure Boot policy setting, which is configured
separately from BitLocker.

Note: If the group policy setting 'Configure TPM platform validation profile for native UEFI
firmware configurations' is enabled and has PCR 7 omitted, Bitlocker will be prevented from using
Secure Boot for platform or Boot Configuration Data (BCD) integrity validation.

Warning: Disabling this policy may result in BitLocker recovery when firmware is updated. If you
disable this policy, suspend BitLocker prior to applying firmware updates.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Allow Secure Boot for integrity validation";
solution = "Set following UI path accordingly:
Windows Components/BitLocker Drive Encryption/Operating System Drives/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\FVE";
item = "OSAllowSecureBootForIntegrity";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
