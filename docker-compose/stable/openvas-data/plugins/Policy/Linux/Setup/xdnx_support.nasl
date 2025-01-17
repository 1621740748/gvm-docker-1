# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.109736");
  script_version("2021-03-12T09:39:13+0000");
  script_tag(name:"last_modification", value:"2021-03-12 09:39:13 +0000 (Fri, 12 Mar 2021)");
  script_tag(name:"creation_date", value:"2019-01-16 08:27:47 +0100 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: XD/NX support");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("ssh_authorization.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Status", type:"radio", value:"Enabled;Disabled", id:1);

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 1.5.2 Ensure XD/NX support is enabled (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies");

  script_tag(name:"summary", value:"The 'No Execute' or 'Execute Disable' functionality marks areas
of memory as non-executable. No code can be executed in these areas of the memory. NX/DX support
enhances the protection against buffer overflow attacks.");
  exit(0);
}

include( "ssh_func.inc" );
include( "policy_functions.inc" );

cmd = "journalctl | grep 'kernel: NX'";
title = "XD/NX support";
solution = "Install a kernel with PAE support (32 bit systems only). Configure XD/NX support in bios.";
test_type = "SSH_Cmd";
default = script_get_preference( "Status", id:1 );

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
} else if( ! cmd_return = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Command did not return anything";
} else {

  if( cmd_return =~ "protection:\s+active" ) {
    value = "Enabled";
  } else {
    value = "Disabled";
  }

  compliant = policy_setting_exact_match( value:value, set_point:default );

}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );
