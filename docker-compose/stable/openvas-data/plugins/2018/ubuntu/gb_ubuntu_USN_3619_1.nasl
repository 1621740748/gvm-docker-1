###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux USN-3619-1
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
  script_oid("1.3.6.1.4.1.25623.1.0.843496");
  script_version("2021-06-03T11:00:21+0000");
  script_tag(name:"last_modification", value:"2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-06 09:52:06 +0200 (Fri, 06 Apr 2018)");
  script_cve_id("CVE-2017-16995", "CVE-2017-0861", "CVE-2017-1000407", "CVE-2017-11472",
                "CVE-2017-15129", "CVE-2017-16528", "CVE-2017-16532", "CVE-2017-16536",
                "CVE-2017-16537", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16649",
                "CVE-2017-16650", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913",
                "CVE-2017-16914", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17449",
                "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-17741", "CVE-2017-17805",
                "CVE-2017-17806", "CVE-2017-17807", "CVE-2017-17862", "CVE-2017-18075",
                "CVE-2017-18203", "CVE-2017-18204", "CVE-2017-18208", "CVE-2017-7518",
                "CVE-2018-1000026", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5344",
                "CVE-2018-6927", "CVE-2018-7492", "CVE-2018-8043");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-05 20:15:00 +0000 (Tue, 05 Jan 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("Ubuntu Update for linux USN-3619-1");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Jann Horn discovered that the Berkeley
  Packet Filter (BPF) implementation in the Linux kernel improperly performed sign
  extension in some situations. A local attacker could use this to cause a denial
  of service (system crash) or possibly execute arbitrary code. (CVE-2017-16995)
  It was discovered that a race condition leading to a use-after-free
  vulnerability existed in the ALSA PCM subsystem of the Linux kernel. A local
  attacker could use this to cause a denial of service (system crash) or possibly
  execute arbitrary code. (CVE-2017-0861) It was discovered that the KVM
  implementation in the Linux kernel allowed passthrough of the diagnostic I/O
  port 0x80. An attacker in a guest VM could use this to cause a denial of service
  (system crash) in the host OS. (CVE-2017-1000407) It was discovered that an
  information disclosure vulnerability existed in the ACPI implementation of the
  Linux kernel. A local attacker could use this to expose sensitive information
  (kernel memory addresses). (CVE-2017-11472) It was discovered that a
  use-after-free vulnerability existed in the network namespaces implementation in
  the Linux kernel. A local attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code. (CVE-2017-15129) It was
  discovered that the Advanced Linux Sound Architecture (ALSA) subsystem in the
  Linux kernel contained a use-after-free when handling device removal. A
  physically proximate attacker could use this to cause a denial of service
  (system crash) or possibly execute arbitrary code. (CVE-2017-16528) Andrey
  Konovalov discovered that the usbtest device driver in the Linux kernel did not
  properly validate endpoint metadata. A physically proximate attacker could use
  this to cause a denial of service (system crash). (CVE-2017-16532) Andrey
  Konovalov discovered that the Conexant cx231xx USB video capture driver in the
  Linux kernel did not properly validate interface descriptors. A physically
  proximate attacker could use this to cause a denial of service (system crash).
  (CVE-2017-16536) Andrey Konovalov discovered that the SoundGraph iMON USB driver
  in the Linux kernel did not properly validate device metadata. A physically
  proximate attacker could use this to cause a denial of service (system crash).
  (CVE-2017-16537) Andrey Konovalov discovered that the IMS Passenger Control Unit
  USB driver in the Linux kernel did not properly validate device descriptors. A
  physically proximate attacker could use this to cause a denial of service
  (system crash). (CVE-2017-16645) Andrey Konovalov discovered that the DiBcom
  DiB0700 USB DVB driver in the Linux kernel di ... Description truncated, for
  more information please check the Reference URL");
  script_tag(name:"affected", value:"linux on Ubuntu 16.04 LTS");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"USN", value:"3619-1");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3619-1/");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04 LTS");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "UBUNTU16.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-1020-kvm", ver:"4.4.0-1020.25", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-1054-aws", ver:"4.4.0-1054.63", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-1086-raspi2", ver:"4.4.0-1086.94", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-1088-snapdragon", ver:"4.4.0-1088.93", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-119-generic", ver:"4.4.0-119.143", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-119-generic-lpae", ver:"4.4.0-119.143", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-119-lowlatency", ver:"4.4.0-119.143", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-119-powerpc-e500mc", ver:"4.4.0-119.143", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-119-powerpc-smp", ver:"4.4.0-119.143", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-119-powerpc64-emb", ver:"4.4.0-119.143", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-4.4.0-119-powerpc64-smp", ver:"4.4.0-119.143", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1054.56", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.119.125", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.4.0.119.125", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1020.19", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.119.125", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-e500mc", ver:"4.4.0.119.125", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc-smp", ver:"4.4.0.119.125", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-emb", ver:"4.4.0.119.125", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-powerpc64-smp", ver:"4.4.0.119.125", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-raspi2", ver:"4.4.0.1086.86", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.4.0.1088.80", rls:"UBUNTU16.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
