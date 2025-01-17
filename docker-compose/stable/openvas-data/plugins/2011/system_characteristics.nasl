###############################################################################
# OpenVAS Vulnerability Test
#
# Show System Characteristics
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103999");
  script_version("2021-01-18T10:34:23+0000");
  script_tag(name:"last_modification", value:"2021-01-18 10:34:23 +0000 (Mon, 18 Jan 2021)");
  script_tag(name:"creation_date", value:"2011-03-08 16:17:59 +0100 (Tue, 08 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Show System Characteristics");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("kb_2_sc.nasl", "gb_nist_win_oval_sys_char_generator.nasl");
  script_mandatory_keys("system_characteristics/created");

  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-20.08/en/compliance-and-special-scans.html#running-an-oval-system-characteristics-scan");

  script_tag(name:"summary", value:"Show OVAL System Characteristics if they have been previously gathered and are available
  in the Knowledge Base.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

if( get_kb_item( "SMB/WindowsVersion" ) ) {
  sc = get_kb_item( "nist_windows_system_characteristics" );
} else {
  sc = get_kb_item( "system_characteristics" );
}

if( sc ) {
  log_message( port:0, data:sc, proto:"OVAL-SC" );
}

exit( 0 );
