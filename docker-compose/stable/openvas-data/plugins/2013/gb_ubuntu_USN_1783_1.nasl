###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1783_1.nasl 14132 2019-03-13 09:25:59Z cfischer $
#
# Ubuntu Update for bind9 USN-1783-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1783-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.841381");
  script_version("$Revision: 14132 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-04-02 12:27:23 +0530 (Tue, 02 Apr 2013)");
  script_cve_id("CVE-2013-2266");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name:"USN", value:"1783-1");
  script_name("Ubuntu Update for bind9 USN-1783-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04 LTS|11\.10|10\.04 LTS|12\.10)");
  script_tag(name:"affected", value:"bind9 on Ubuntu 12.10,
  Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 10.04 LTS");
  script_tag(name:"insight", value:"Matthew Horsfall discovered that Bind incorrectly handled regular
  expression checking. A remote attacker could use this flaw to cause Bind to
  consume an excessive amount of memory, possibly resulting in a denial of
  service. This issue was corrected by disabling RDATA regular expression
  syntax checking.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.8.1.dfsg.P1-4ubuntu0.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdns81", ver:"1:9.8.1.dfsg.P1-4ubuntu0.6", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU11.10")
{

  if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.7.3.dfsg-1ubuntu4.6", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdns69", ver:"1:9.7.3.dfsg-1ubuntu4.6", rls:"UBUNTU11.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.7.0.dfsg.P1-1ubuntu0.9", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdns64", ver:"1:9.7.0.dfsg.P1-1ubuntu0.9", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "UBUNTU12.10")
{

  if ((res = isdpkgvuln(pkg:"bind9", ver:"1:9.8.1.dfsg.P1-4.2ubuntu3.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libdns81", ver:"1:9.8.1.dfsg.P1-4.2ubuntu3.2", rls:"UBUNTU12.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
