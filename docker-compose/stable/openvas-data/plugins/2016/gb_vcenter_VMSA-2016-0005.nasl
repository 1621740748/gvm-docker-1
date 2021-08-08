# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:vmware:vcenter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105731");
  script_cve_id("CVE-2016-3427", "CVE-2016-2077");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2021-04-16T06:57:08+0000");
  script_name("VMware Security Updates for vCenter Server (VMSA-2016-0005)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0005.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable build is present on the
  target host.");

  script_tag(name:"insight", value:"The RMI server of Oracle JRE JMX deserializes any class when deserializing
  authentication credentials. This may allow a remote, unauthenticated attacker to cause deserialization flaws
  and execute their commands.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Mware product updates address critical and important security issues.");

  script_tag(name:"affected", value:"vCenter Server 6.0 on Windows without workaround of KB 2145343

  vCenter Server 6.0 on Linux (VCSA) prior to 6.0.0b

  vCenter Server 5.5 prior to 5.5 U3d (on Windows), 5.5 U3 (VCSA)

  vCenter Server 5.1 prior to 5.1 U3b

  vCenter Server 5.0 prior to 5.0 U3e");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-05-26 11:51:22 +0200 (Thu, 26 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("vmware/vcenter/detected", "vmware/vcenter/build");

  exit(0);
}

include("vmware_esx.inc");
include("host_details.inc");
include("os_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! build = get_kb_item( "vmware/vcenter/build" ) )
  exit( 0 );

if( version == "5.0.0" )
  if( int( build ) < int( 3073236 ) )
    fix = "5.0 U3e (+ KB 2144428 on Windows)";

if( version == "5.1.0" )
  if( int( build ) < int( 3070521 ) )
    fix = "5.1 U3d / 5.1 U3b with KB 2144428 on Windows";

if( version == "6.0.0" )
  if( int( build ) < int( 2776510 ) )
    fix = "6.0.0b (+ KB 2145343 on Windows)";

if( os_host_runs( "Windows" ) == "yes" ) {
  if( version == "5.5.0" )
    if( int( build ) < int( 3252642 ) )
      fix = "5.5 U3d / 5.5 U3b + KB 2144428";
} else if( os_host_runs( "Linux" ) == "yes" ) {
  if( version == "5.5.0" )
    if( int( build ) < int( 3000241 ) )
      fix = "5.5 U3";
}

if( fix ) {
  security_message( port:0, data:esxi_remote_report( ver:version, build:build, fixed_build:fix, typ:"vCenter" ) );
  exit( 0 );
}

exit( 99 );
