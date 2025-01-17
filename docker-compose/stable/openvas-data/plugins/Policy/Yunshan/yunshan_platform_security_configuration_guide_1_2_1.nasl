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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150674");
  script_version("2021-07-31T11:14:56+0000");
  script_tag(name:"last_modification", value:"2021-07-31 11:14:56 +0000 (Sat, 31 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 11:41:38 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: The protocol inbound ssh port 830 is not configured");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("Compliance/Launch", "huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"Enable the NETCONF dedicated port.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd = "display current-configuration configuration ssh";
title = "The protocol inbound ssh port 830 is not configured";
solution = "If the SNETCONF service is enabled, you are advised to run the protocol inbound ssh
command to configure port 830 for SNETCONF.";
test_type = "SSH_Cmd";
default = "If snetconf server enable is not displayed in the command output, no problem occurs.
If no SSH configuration exists, the problem exists. As long as there is any one, there is no problem.";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
} else {
  if( ! value = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                                retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command did not return anything";
  } else if( value !~ "snetconf\s+server\s+enable" ) {
    compliant = "yes";
    comment = "'snetconf server enable' is not displayed in the command output";
  } else {
    cmd2 = "display current-configuration configuration netconf";
    if( ! value2 = ssh_cmd( socket:sock, cmd:cmd2, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                                retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
      compliant = "no";
      value = "error";
      comment = "Command '" + cmd2 + "' did not return anything";
    } else if ( value2 =~ "protocol\s+inbound\s+ssh" ) {
      compliant = "yes";
      value += '\n\n' + value2;
    } else {
      compliant = "no";
      value += '\n\n' + value2;
    }
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit(0);
