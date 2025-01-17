###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Domino iCalendar Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901157");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_bugtraq_id(43219);
  script_cve_id("CVE-2010-3407");

  script_name("IBM Lotus Domino iCalendar Remote Stack Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15005");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2381");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Sep/1024448.html");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21446515");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute arbitrary code
  in the context of the 'nrouter.exe' Lotus Domino server process. Failed
  attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"IBM Lotus Domino Versions 8.0.x before 8.0.2 FP5 and 8.5.x before 8.5.1 FP2");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in the 'MailCheck821Address()'
  function within nnotes.dll when copying an email address using the
  'Cstrcpy()' library function. This can be exploited to cause a stack-based
  buffer overflow via an overly long 'ORGANIZER:mailto' iCalendar header.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Domino version 8.5.2, 8.5.1 Fix Pack 2 or 8.0.2 Fix Pack 5.");

  script_tag(name:"summary", value:"The host is running IBM Lotus Domino Server and is prone to remote
  stack buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if( version_in_range( version:version, test_version:"8", test_version2:"8.0.2.4" ) ||
    version_in_range( version:version, test_version:"8.5", test_version2:"8.5.1.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"8.0.2 FP5 / 8.5.1 FP2 / 8.5.2" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
