###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-fsl-imx51 USN-1204-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1204-1/");
  script_oid("1.3.6.1.4.1.25623.1.0.840744");
  script_version("2021-05-19T13:10:04+0000");
  script_tag(name:"last_modification", value:"2021-05-19 13:10:04 +0000 (Wed, 19 May 2021)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 15:45:00 +0000 (Tue, 04 Aug 2020)");
  script_xref(name:"USN", value:"1204-1");
  script_cve_id("CVE-2010-3859", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4668", "CVE-2010-4175", "CVE-2010-4242", "CVE-2010-4243", "CVE-2010-4251", "CVE-2010-4805", "CVE-2010-4526", "CVE-2010-4649", "CVE-2011-1044", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1020", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-2534", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1478", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1598", "CVE-2011-1770", "CVE-2011-1833", "CVE-2011-2484", "CVE-2011-2492", "CVE-2011-2699", "CVE-2011-2918");
  script_name("Ubuntu Update for linux-fsl-imx51 USN-1204-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU10\.04 LTS");
  script_tag(name:"summary", value:"Ubuntu Update for Linux kernel vulnerabilities USN-1204-1");
  script_tag(name:"affected", value:"linux-fsl-imx51 on Ubuntu 10.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Dan Rosenberg discovered that the Linux kernel TIPC implementation
  contained multiple integer signedness errors. A local attacker could
  exploit this to gain root privileges. (CVE-2010-3859)

  Dan Rosenberg discovered that multiple terminal ioctls did not correctly
  initialize structure memory. A local attacker could exploit this to read
  portions of kernel stack memory, leading to a loss of privacy.
  (CVE-2010-4075, CVE-2010-4076, CVE-2010-4077)

  Dan Rosenberg discovered that the socket filters did not correctly
  initialize structure memory. A local attacker could create malicious
  filters to read portions of kernel stack memory, leading to a loss of
  privacy. (CVE-2010-4158)

  Dan Rosenberg discovered that the Linux kernel L2TP implementation
  contained multiple integer signedness errors. A local attacker could
  exploit this to crash the kernel, or possibly gain root privileges.
  (CVE-2010-4160)

  Dan Rosenberg discovered that certain iovec operations did not calculate
  page counts correctly. A local attacker could exploit this to crash the
  system, leading to a denial of service. (CVE-2010-4162)

  Dan Rosenberg discovered that the SCSI subsystem did not correctly validate
  iov segments. A local attacker with access to a SCSI device could send
  specially crafted requests to crash the system, leading to a denial of
  service. (CVE-2010-4163, CVE-2010-4668)

  Dan Rosenberg discovered that the RDS protocol did not correctly check
  ioctl arguments. A local attacker could exploit this to crash the system,
  leading to a denial of service. (CVE-2010-4175)

  Alan Cox discovered that the HCI UART driver did not correctly check if a
  write operation was available. If the mmap_min-addr sysctl was changed from
  the Ubuntu default to a value of 0, a local attacker could exploit this
  flaw to gain root privileges. (CVE-2010-4242)

  Brad Spengler discovered that the kernel did not correctly account for
  userspace memory allocations during exec() calls. A local attacker could
  exploit this to consume all system memory, leading to a denial of service.
  (CVE-2010-4243)

  Alex Shi and Eric Dumazet discovered that the network stack did not
  correctly handle packet backlogs. A remote attacker could exploit this by
  sending a large amount of network traffic to cause the system to run out of
  memory, leading to a denial of service. (CVE-2010-4251, CVE-2010-4805)

  It was discovered that the ICMP stack did not correctly handle certain
  unreachable messages. If a remote attacker were able to acquire a socket
  lock, they could send specially  ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.31-610-imx51", ver:"2.6.31-610.28", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
