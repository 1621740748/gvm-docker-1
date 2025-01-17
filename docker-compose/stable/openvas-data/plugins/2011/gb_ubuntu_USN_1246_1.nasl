###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-1246-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1246-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840793");
  script_version("2020-08-04T07:16:50+0000");
  script_tag(name:"last_modification", value:"2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-10-31 13:45:00 +0100 (Mon, 31 Oct 2011)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"USN", value:"1246-1");
  script_cve_id("CVE-2011-2213", "CVE-2011-2497", "CVE-2011-2695", "CVE-2011-2700",
                "CVE-2011-2723", "CVE-2011-2928", "CVE-2011-3188", "CVE-2011-3191");
  script_name("Ubuntu Update for linux USN-1246-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1246-1");
  script_tag(name:"affected", value:"linux on Ubuntu 11.04");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Dan Rosenberg discovered that the IPv4 diagnostic routines did not
  correctly validate certain requests. A local attacker could exploit this to
  consume CPU resources, leading to a denial of service. (CVE-2011-2213)

  Dan Rosenberg discovered that the Bluetooth stack incorrectly handled
  certain L2CAP requests. If a system was using Bluetooth, a remote attacker
  could send specially crafted traffic to crash the system or gain root
  privileges. (CVE-2011-2497)

  It was discovered that the EXT4 filesystem contained multiple off-by-one
  flaws. A local attacker could exploit this to crash the system, leading to
  a denial of service. (CVE-2011-2695)

  Mauro Carvalho Chehab discovered that the si4713 radio driver did not
  correctly check the length of memory copies. If this hardware was
  available, a local attacker could exploit this to crash the system or gain
  root privileges. (CVE-2011-2700)

  Herbert Xu discovered that certain fields were incorrectly handled when
  Generic Receive Offload (CVE-2011-2723)

  Time Warns discovered that long symlinks were incorrectly handled on Be
  filesystems. A local attacker could exploit this with a malformed Be
  filesystem and crash the system, leading to a denial of service.
  (CVE-2011-2928)

  Dan Kaminsky discovered that the kernel incorrectly handled random sequence
  number generation. An attacker could use this flaw to possibly predict
  sequence numbers and inject packets. (CVE-2011-3188)

  Darren Lavender discovered that the CIFS client incorrectly handled certain
  large values. A remote attacker with a malicious server could exploit this
  to crash the system or possibly execute arbitrary code as the root user.
  (CVE-2011-3191)");
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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-generic", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-generic-pae", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-omap", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-powerpc", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-powerpc-smp", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-powerpc64-smp", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-server", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-versatile", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.38-12-virtual", ver:"2.6.38-12.51", rls:"UBUNTU11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
