###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-aws USN-3582-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.843459");
  script_version("2021-06-04T02:00:20+0000");
  script_tag(name:"last_modification", value:"2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-22 15:56:55 +0100 (Thu, 22 Feb 2018)");
  script_cve_id("CVE-2017-17712", "CVE-2015-8952", "CVE-2017-12190", "CVE-2017-15115",
                "CVE-2017-8824", "CVE-2017-5715");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-08 18:28:00 +0000 (Wed, 08 May 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux-aws USN-3582-2");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"USN-3582-1 fixed vulnerabilities in the
  Linux kernel for Ubuntu 16.04 LTS. This update provides the corresponding
  updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for
  Ubuntu 14.04 LTS. Mohamed Ghannam discovered that the IPv4 raw socket
  implementation in the Linux kernel contained a race condition leading to
  uninitialized pointer usage. A local attacker could use this to cause a denial
  of service or possibly execute arbitrary code. (CVE-2017-17712) Laurent Guerby
  discovered that the mbcache feature in the ext2 and ext4 filesystems in the
  Linux kernel improperly handled xattr block caching. A local attacker could use
  this to cause a denial of service. (CVE-2015-8952) Vitaly Mayatskikh discovered
  that the SCSI subsystem in the Linux kernel did not properly track reference
  counts when merging buffers. A local attacker could use this to cause a denial
  of service (memory exhaustion). (CVE-2017-12190) ChunYu Wang discovered that a
  use-after-free vulnerability existed in the SCTP protocol implementation in the
  Linux kernel. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code, (CVE-2017-15115) Mohamed
  Ghannam discovered a use-after-free vulnerability in the DCCP protocol
  implementation in the Linux kernel. A local attacker could use this to cause a
  denial of service (system crash) or possibly execute arbitrary code.
  (CVE-2017-8824) USN-3540-2 mitigated CVE-2017-5715 (Spectre Variant 2) for the
  amd64 architecture in Ubuntu 14.04 LTS. This update provides the compiler-based
  retpoline kernel mitigation for the amd64 and i386 architectures. Original
  advisory details: Jann Horn discovered that microprocessors utilizing
  speculative execution and branch prediction may allow unauthorized memory reads
  via sidechannel attacks. This flaw is known as Spectre. A local attacker could
  use this to expose sensitive information, including kernel memory.
  (CVE-2017-5715)");
  script_tag(name:"affected", value:"linux-aws on Ubuntu 14.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"USN", value:"3582-2");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3582-2/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU14.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-1014-aws", ver:"4.4.0-1014.14", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-116-generic", ver:"4.4.0-116.140~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-116-generic-lpae", ver:"4.4.0-116.140~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-116-lowlatency", ver:"4.4.0-116.140~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-116-powerpc-e500mc", ver:"4.4.0-116.140~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-116-powerpc-smp", ver:"4.4.0-116.140~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-116-powerpc64-emb", ver:"4.4.0-116.140~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-116-powerpc64-smp", ver:"4.4.0-116.140~14.04.1", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1014.14", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-xenial", ver:"4.4.0.116.98", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.116.98", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.116.98", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc-lts-xenial", ver:"4.4.0.116.98", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-smp-lts-xenial", ver:"4.4.0.116.98", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-emb-lts-xenial", ver:"4.4.0.116.98", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-smp-lts-xenial", ver:"4.4.0.116.98", rls:"UBUNTU14.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
