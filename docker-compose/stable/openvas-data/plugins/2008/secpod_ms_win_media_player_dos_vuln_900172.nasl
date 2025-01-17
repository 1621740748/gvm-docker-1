##############################################################################
# OpenVAS Vulnerability Test
# Description: Microsoft Windows Media Player 'MIDI' or 'DAT' File DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900172");
  script_version("2020-06-09T11:16:08+0000");
  script_tag(name:"last_modification", value:"2020-06-09 11:16:08 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2008-11-11 15:58:44 +0100 (Tue, 11 Nov 2008)");
  script_bugtraq_id(32077);
  script_cve_id("CVE-2008-4927");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Microsoft Windows Media Player 'MIDI' or 'DAT' File DoS Vulnerability");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_mandatory_keys("Win/MediaPlayer/Ver");

  script_xref(name:"URL", value:"http://www.securityfocus.com/data/vulnerabilities/exploits/32077.py");

  script_tag(name:"impact", value:"Successful exploitation will cause denial of service.");

  script_tag(name:"affected", value:"Microsoft Windows Media Player versions 9.x, 10.x and 11.x.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with Windows Media Player and is prone to
  denial of service vulnerability.");

  script_tag(name:"insight", value:"The vulnerability is due to error in handling 'MIDI' or 'DAT' file,
  related to 'MThd Header Parsing'.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

if( ! version = get_kb_item( "Win/MediaPlayer/Ver" ) ) exit( 0 );

if( version =~ "^(9|1[01])\..*$" ) {
  security_message( port:0 );
  exit( 0 );
}

exit( 99 );
