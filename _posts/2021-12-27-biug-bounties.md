---
use_math: true
title: "Biug Bounties and HyperV RCE Research"
tags:
  - fuzzing
  - bug
  - bounties
  - research
---

{% include toc %}

# Hyper-V: Post#1

## intro
This is a post I should have posted a long time ago, but I didn't because of various reasons: laziness, lack of time, greed, eating bananas, composting shits, kind of burnout, ego to make it to BH USA first (and been screwed each time with different set of Hyper-V RCEs 4 times in a row ahaha; just a reference to highlight that conferences are not the only way to go - note for myself in the future :). 

In a series of blogpost that I am writing, I aim to look at RCE bugs that are in scope for [MSFT Hyper-Vbounty](https://www.microsoft.com/en-us/msrc/bounty-hyper-v) to study the state of Hyper-V Vulnerability research: state of code, type of bugs, complexity of reaching or detecting them, my 5cents regarding recent confusion about what is in scope and why, and finally some examples for setbacks of big bounties. For the next posts, I plan on discussing how to setup effective Hyper-V fuzzing and research environment, the type of fuzzers and automation, and as a bonus pinpointing targets that are not so obvious, and areas that I did not cover properly yet. Posts may or may not contain easter eggs, happy hunting!

I will try to be brief cuz it is not rocket science, so without further ado let's dig in.

## bugzzz ( fyi all bugs discussed here are fixed )

### vsmb - nice bugs : fuzzing is cool [CVE-2020-17095]
  - vmusrv.dll : responsible for efficient sharing files host-guest
  - Is there { cancel / flush / remove / other early drop of packet } logic in your target? If you haven't fuzzed those yet then you should: it usually is bull's eye without question.
  
```
long Smb2ExecuteCancel(_SRV_WORK_ITEM *param_1)
{  
  SrvCancelWorkItem((_SRV_WORK_ITEM *)piVar2,2); // here can deref UAF too

  LOCK();
  iVar1 = *piVar2;
  *piVar2 = *piVar2 + -1; //refcounter

  if (iVar1 == 1) { // boom
    SrvFreeWorkItem((_SRV_WORK_ITEM *)piVar2);
      ->  long Smb2CleanupWorkItem(_SRV_WORK_ITEM *param_1)
         ->  Remove((RfsTable ptr ptr)(p_Var5 + 0x28),(uint)uVar6,false); // unreferenced from list after item marked for deletion -> ref counter == 0
```
  - takes me longer time to dig this one out because I miss the sync/async flag of additional **cancel** packet functionality in documentation, and here we have

```
long Smb2ValidateCancel(_SRV_WORK_ITEM param_1) 
{
…
    if (((byte)p_Var7[0x10] & 2) == 0) { // sync
    …
    else { // async
      if ((ulonglong )(p_Var7 + 0x20) < 0x100000000) {
        pvVar8 = Lookup((RfsTable *)(p_Var6 + 0x28),(uint)(ulonglong *)(p_Var7 + 0x20));
      }
      
void * __thiscall Lookup(RfsTable *this,uint param_1)
{
  void *pvVar1;
  AcquireSRWLockShared((PSRWLOCK)this);

  pvVar1 = (void *)0x0;
  if ((((param_1 != 0) && (param_1 < *(uint *)(this + 0x3c) || param_1 == *(uint *)(this + 0x3c)))
      && (pvVar1 = *(void *)((longlong *)(this + 8) + (ulonglong)(param_1 - 1) * 8),
         pvVar1 != (void )0x0)) && ((code **)(this + 0x48) != (code *)0x0)) {
    (**(code **)(this + 0x48))();
  }  
  ReleaseSRWLockShared((PSRWLOCK)this);
  return pvVar1; // we return plain ptr in async manner
}
```
  - I found it while analyzing code coverage
  - The root cause: you can race ChangeNotify + async Cancel packets, ChangeNotify will try to delete object as the refcount of its work item drops to 0, but cancel can race this process while work_item is still found in LookupList. Thus later execution of cancel packet ( as async flag was done, first phase was just by validation of cancel packet and looking up - refcounting from 0 back to 1 ), will deref free-ed work_item. At first sight, it all seemed good, refcounting in place, locking too.. Though strange logic of removing an object from a list from objects own destructor. Also interesting we can acquire object which have refcount == 0 once it already acquired refcount >= 1
  - How I fuzzed it: adding a particular flag to cancel packet, and let automation do its job in 5mins hit.. and to be honest looked at that logic with my eyes before triggering it by fuzzer and ... I did not find it:
 
```
vmusrv!SrvFreeWorkItem+0x1bc:
00007ffbc1b127f8 4c397f50        cmp     qword ptr [rdi+50h],r15 ds:000002109cd3ed40=????????????????
```
  - How to reach to fuzz : 
    + docker + [vsmb rewriting packets](https://github.com/rezer0dai/proxyserver)
    + loading vmusrv.dll as standalone : [JPEG2000 - Fuzzing DLL on Linux](https://ruxcon.org.au/assets/2016/slides/j00ru-ruxcon2016.pdf) or [hAFL1 ~ fuzzing VMSwitch w/o Hyper-V](https://www.guardicore.com/labs/hafl1-our-journey-of-fuzzing-hyper-v-and-discovering-a-critical-0-day/)
    
  
  > vsmb, older bug, bonus:
  
      - open vsmb file
      - get a predictable file handle
      - bug: race open + close with predictable handle
      - cve: forgotten.. around 2018
      - how I fuzzed it: understanding of target (predictable handle + that packet is tied to file handles) and adding quirks to fuzzing (prediction of the handle before its creation, dangling handles), not especially focused on that logic, just taking it into account (fuzzing is specific per target)
      
### 9p - ugly one : may the force be with you [CVE-2021-26867]
  - vp9fs.dll : responsible for efficient sharing files host-guest
  - again remove: 
  
```
void operator()( param_1)
    …:
    TVar2 = operator()(this); // Remove RequestInfo from LinkedList
      -> void __thiscall Remove(LinkedList<struct_p9fs::Handler::RequestInfo> *this,RequestInfo *param_1)

    …

    ~((longlong)(param_1 + 0xb0)); // Free RequestInfo*
```
  - well this looks especially solid, also order remove + delete looks good. but problem is that remove actually to happen, callstack must look like this 
  
```
FLUSH_ENTRYYY
rcx=000001faa4395ef0
REMOVE
rcx=000001faa1158f10
rdx=000001faa4192fe0
Child-SP          RetAddr           Call Site
00000022`2e97e618 00007ffc`b93d83c0 vp9fs!p9fs::util::LinkedList<p9fs::Handler::RequestInfo>::Remove
00000022`2e97e620 00007ffc`b93d61c3 vp9fs!p9fs::Handler::ProcessMessage$_ResumeCoro$2+0x1240
00000022`2e97ec40 00007ffc`b93afa34 vp9fs!p9fs::Handler::ProcessMessage$_InitCoro$1+0x12f
00000022`2e97ece0 00007ffc`b93cc061 vp9fs!p9fs::Handler::ProcessMessage+0x68
00000022`2e97f140 00007ffc`b93cbcc4 vp9fs!<lambda_8c0f73b7442b169e13d3115da82aed7d>$_ResumeCoro$2::operator()+0x341
00000022`2e97f410 00007ffc`b93afd56 vp9fs!<lambda_8c0f73b7442b169e13d3115da82aed7d>$_InitCoro$1::operator()+0xd0
00000022`2e97f480 00007ffc`b93caa73 vp9fs!<lambda_8c0f73b7442b169e13d3115da82aed7d>::operator()+0x46
00000022`2e97f5f0 00007ffc`b93a6a32 vp9fs!<lambda_1cce8f953904a6d717908b4c35b3a59d>$_ResumeCoro$2::operator()+0xd3
00000022`2e97f7e0 00007ffc`b93bf641 vp9fs!p9fs::Scheduler::RunAndRelease+0xbe
00000022`2e97f820 00007ffc`cec631e0 vp9fs!p9fs::CoroutineIoIssuer::Callback+0x71
00000022`2e97f850 00007ffc`d0feecd9 KERNELBASE!BasepTpIoCallback+0x50
00000022`2e97f8a0 00007ffc`d0fc2536 ntdll!TppIopExecuteCallback+0x129
00000022`2e97f920 00007ffc`cfa27034 ntdll!TppWorkerThread+0x456
00000022`2e97fc20 00007ffc`d0ffcec1 KERNEL32!BaseThreadInitThunk+0x14
00000022`2e97fc50 00000000`00000000 ntdll!RtlUserThreadStart+0x21

FREE
rbx=000001faa4196fb8
rcx=000001faa4192fe0

Child-SP          RetAddr           Call Site
00000022`2e97f5c0 00007ffc`b93cb08c vp9fs!<lambda_8c0f73b7442b169e13d3115da82aed7d>::~<lambda_8c0f73b7442b169e13d3115da82aed7d>+0xd
00000022`2e97f5f0 00007ffc`b93a6a32 vp9fs!<lambda_1cce8f953904a6d717908b4c35b3a59d>$_ResumeCoro$2::operator()+0x6ec
00000022`2e97f7e0 00007ffc`b93bf641 vp9fs!p9fs::Scheduler::RunAndRelease+0xbe
00000022`2e97f820 00007ffc`cec631e0 vp9fs!p9fs::CoroutineIoIssuer::Callback+0x71
00000022`2e97f850 00007ffc`d0feecd9 KERNELBASE!BasepTpIoCallback+0x50
00000022`2e97f8a0 00007ffc`d0fc2536 ntdll!TppIopExecuteCallback+0x129
00000022`2e97f920 00007ffc`cfa27034 ntdll!TppWorkerThread+0x456
00000022`2e97fc20 00007ffc`d0ffcec1 KERNEL32!BaseThreadInitThunk+0x14
00000022`2e97fc50 00000000`00000000 ntdll!RtlUserThreadStart+0x21
```
  - note : we are about here to call from operator : ```vp9fs!<lambda_1cce8f953904a6d717908b4c35b3a59d>$_ResumeCoro$2::operator()```
  
  - pay attention that callstack is quite deep to actually reach the Remove function, but here it comes magic of c++ and throwing exceptions before reaching Remove, and vioala we got stack like this :
  
```
FLUSH_ENTRYYY
rcx=000001faa43a1ef0
onecore\vm\dv\storage\plan9\dll\windows\p9io.cpp(128)\vp9fs.dll!00007FFCB93DFFCF: (caller: 00007FFCB93DF71A) Exception(1) tid(f9c) 800703E3 The I/O operation has been aborted because of either a thread exit or an application request.
(6c0.f9c): C++ EH exception - code e06d7363 (first chance)
(6c0.f9c): C++ EH exception - code e06d7363 (first chance)
(6c0.f9c): C++ EH exception - code e06d7363 (first chance)
(6c0.f9c): C++ EH exception - code e06d7363 (first chance)
onecore\vm\dv\storage\plan9\dll\p9handler.cpp(1039)\vp9fs.dll!00007FFCB93E562B: (caller: 00007FFCB93CBCC4) LogHr(1) tid(f9c) 800703E3 The I/O operation has been aborted because of either a thread exit or an application request.
    Msg:[onecore\vm\dv\storage\plan9\dll\windows\p9io.cpp(128)\vp9fs.dll!00007FFCB93DFFCF: (caller: 00007FFCB93DF71A) Exception(1) tid(f9c) 800703E3 The I/O operation has been aborted because of either a thread exit or an application request.
]
FREE
rbx=000001faa41a2fb8
rcx=000001faa419efe0
Child-SP          RetAddr           Call Site
00000022`2e97f5c0 00007ffc`b93cb08c vp9fs!<lambda_8c0f73b7442b169e13d3115da82aed7d>::~<lambda_8c0f73b7442b169e13d3115da82aed7d>+0xd
00000022`2e97f5f0 00007ffc`b93a6a32 vp9fs!<lambda_1cce8f953904a6d717908b4c35b3a59d>$_ResumeCoro$2::operator()+0x6ec
00000022`2e97f7e0 00007ffc`b93bf641 vp9fs!p9fs::Scheduler::RunAndRelease+0xbe
00000022`2e97f820 00007ffc`cec631e0 vp9fs!p9fs::CoroutineIoIssuer::Callback+0x71
00000022`2e97f850 00007ffc`d0feecd9 KERNELBASE!BasepTpIoCallback+0x50
00000022`2e97f8a0 00007ffc`d0fc2536 ntdll!TppIopExecuteCallback+0x129
00000022`2e97f920 00007ffc`cfa27034 ntdll!TppWorkerThread+0x456
00000022`2e97fc20 00007ffc`d0ffcec1 KERNEL32!BaseThreadInitThunk+0x14
00000022`2e97fc50 00000000`00000000 ntdll!RtlUserThreadStart+0x21
```

  - aka, we bubble out from exception (overload of packets) without removing struct from list, but deleting it anyway, ouch ...
  
  - root cause: when exception unwinding happens, it is forgotten to handle proper removing object from list but free is done correctly :)
  
```
vp9fs!p9fs::Handler::HandleFlush$_ResumeCoro$2+0x48c:
00007ff8e2df033c 0fb74918        movzx   ecx,word ptr [rcx+18h] ds:000002542129dff8=????
```
  
  - how fuzzed it: when doing code coverage you are restricted to a few dozens of calls due to reproducibility, also you want to have as many calls enabled (open, close, flush, cancel, write, seek, attr, etc.). But sometimes brute force and extreme cases do their job, yeah you can call it dummy fuzzing shame on me :( aka total call limit I raised to several thousands, and doing filtering of calls (an only subset of calls will be called per run), moreover sometimes you want to run several fuzzers at once for one target (though not necessarily in this case) , dummy dummy yammy yammy

  - How to reach to fuzz : 
    + tinker [linux kernel code](https://github.com/torvalds/linux/blob/master/net/9p/trans_fd.c) to allow sending packets from your fuzzer
    + or again, load and fuzz standalone

### vmwp - well, what is fuzzing anyway [CVE-2021-28314]
  - vmwp.exe : main process per VM, loading dlls like vmusrv.dll or vp9fs.dll, driver communication like vid, vmswitch, .. 
  - check this, hint ~ refcounting: 
  
```
void __thiscall Teardown(VirtualMachine * this)

1400513bd:

  this_00 = *(WorkerCpuidHandler **)(this + 0x240);
  if (this_00 != (WorkerCpuidHandler *)0x0) {
    puVar7 = *(undefined8 **)(this_00 + 0x30);
    while (puVar7 != *(undefined8 **)(this_00 + 0x38)) {
      (**(code **)(*(longlong *)(*(longlong *)(this_00 + 0x10) + 8) + 0x38))
                ((longlong *)(*(longlong *)(this_00 + 0x10) + 8),*puVar7);
      puVar7 = puVar7 + 1;
    }
    *(undefined8 *)(this_00 + 0x38) = *(undefined8 *)(this_00 + 0x30);
    TeardownRegisteredResults(this_00);
    pIVar5 = (IMetricManager *)(*(longlong *)(this + 0x240) + 8);
    DecrementUserCount((VmSharableObject *)
                       ((type_info *)pIVar5 +
                       *(int *)(*(longlong *)(*(longlong *)(this + 0x240) + 8) + 4)),
                       (type_info *)pIVar5);
    *(undefined8 *)(this + 0x240) = 0;
  }
...

    00007ff78836ad25 vmwp!WorkerCpuidHandler::`vector deleting destructor'+0x0000000000000035
    00007ff7883266ca vmwp!Vml::VmSharableObject::OnLastContainedObjectRemoved+0x000000000000001e
    00007ff788322fbf vmwp!Vml::VmSharableObject::DecrementContainedObjectCount+0x000000000000007b
    00007ff78832307d vmwp!Vml::VmSharableObject::DecrementWeakUserCount+0x000000000000009d
    00007ff788319011 vmwp!Vml::VmSharableObject::DecrementUserCount+0x000000000000630d
    00007ff78836141c vmwp!VirtualMachine::Teardown+0x00000000000001d0
    00007ff78832973a vmwp!WorkerModule::TeardownVirtualMachine+0x00000000000000ae
    00007ff788326bb2 vmwp!WorkerModule::OnVirtualMachinePostFunctional+0x0000000000000012
    00007ff7883237fd vmwp!Vml::VmMethodDelegate<WorkerModule,void,Vml::VmReferencePtr<Vml::VmSharableObject,Vml::VmWeakReferenceTraits> >::Execute+0x000000000000002d
    00007ff788325b65 vmwp!Vml::VmDispatchContext::Invoke+0x000000000000001d
    00007ff788358f6d vmwp!Vml::VmOrderedDispatcher::ProcessQueue+0x000000000000002d
    00007ff78835138d vmwp!Vml::VmMethodDelegate<Vml::VmOrderedThreadpoolDispatcher,void>::Execute+0x000000000000005d
    00007ff7883238bb vmwp!Vml::VmNewThreadpool::FastDispatchWorkCallback+0x000000000000001b
    00007fffcdfd39c0 ntdll!TppWorkpExecuteCallback+0x0000000000000130
    00007fffcdf8276a ntdll!TppWorkerThread+0x000000000000068a
    00007fffcc1e7034 kernel32!BaseThreadInitThunk+0x0000000000000014
    00007fffcdfbcec1 ntdll!RtlUserThreadStart+0x0000000000000021
```
  - and this, hint ~ locking: 
  
```
HandleVndCallback(VndCompletionHandler *this,void *param_1,_VID_MSG_DATA *param_2, _VID_MSG_RETURN_DATA *param_3)
140149ee2:
          if (uVar10 != 0x1000010) {
            this_00 = *(VmSharableObject **)(param_2 + 8);
            *(undefined8 *)(param_2 + 8) = *(undefined8 *)(this_00 + 0x78);
            if ((((uVar10 == 1) || (uVar10 == 7)) || (uVar10 == 9)) ||
               ((0x1000001 < (int)uVar10 &&
                (((int)uVar10 < 0x1000004 ||
                 ((0x100000d < (int)uVar10 && (((int)uVar10 < 0x1000010 || (uVar10 == 0x1000011)))))
                 ))))) {
              ppcVar12 = *(code ***)(this_00 + 0x80);
              if ((uVar10 - 7 & 0xfffffffd) == 0) {
                *local_68 = 0;
                local_c8 = CONCAT44(local_c8._4_4_,0xffffffff);
                ppuVar13 = (undefined **)&DAT_00000002;
                iVar8 = VidHandleMessageAndGetNextMessage(param_1,2,&local_68);
                if (iVar8 == 0) {
                  ppuVar13 = (undefined **)0x26e;
                  Log_Hr(local_res0,0x26e,
                         "onecore\\vm\\worker\\vidpartition\\vndcompletionhandler.cpp",-0x7fff0001);
                  iVar8 = VmlIsDebugTraceEnabled(0);
                  if (iVar8 != 0) {
                    ppuVar13 = &PTR_u_Unexpected_erro_140195b28;
                    VmlDebugTraceEx(0);
                  }
                }
                DecrementUserCount(this_00,(type_info *)ppuVar13);
              }

void __thiscall UnprepareSelf(VND_HANDLER_CONTEXT *this)

{
  type_info *in_RDX;

  if (*(int *)(this + 0x88) != 0) {
    in_RDX = *(type_info **)(this + 0x78);
    (**(code **)(**(longlong **)(this + 0x80) + 0x28))(); //-> vmwp!Vml::VmSharableObject::DecrementUserCount
  }

000000e2`82eff500 00007ff7`88459d2e vmwp!Vml::VmSharableObject::DecrementUserCount+0x59
000000e2`82eff530 00007ff7`88329a6a vmwp!VND_HANDLER_CONTEXT::UnprepareSelf+0x2e
000000e2`82eff560 00007ff7`883267b0 vmwp!Vml::VmSharableObject::Unprepare+0x1e
000000e2`82eff590 00007ff7`88319009 vmwp!Vml::VmSharableObject::OnLastUserRemoved+0x94
000000e2`82eff5d0 00007ff7`8845a057 vmwp!Vml::VmSharableObject::DecrementUserCount+0x6305
000000e2`82eff600 00007ff7`8845b5ac vmwp!VndCompletionHandler::HandleVndCallback+0x227
000000e2`82eff6f0 00007ff7`8845ac69 vmwp!VndCompletionThread::RunSelf+0x10c
000000e2`82eff760 00007fff`cb9b14c2 vmwp!Vml::VmThread::OnRunThread+0x19
000000e2`82eff790 00007fff`ba186a74 ucrtbase!thread_start<unsigned int (__cdecl*)(void *),1>+0x42
000000e2`82eff7c0 00007fff`cc1e7034 vfbasics!AVrfpStandardThreadFunction+0x44
000000e2`82eff800 00007fff`cdfbcec1 kernel32!BaseThreadInitThunk+0x14
000000e2`82eff830 00000000`00000000 ntdll!RtlUserThreadStart+0x21
```
  - The root cause: Read Only State is a beautiful concept i once aspire to. But it can have dangers once your design is not ready for it, aka in this case developer can see read-only access at HandleCallback and skip to do any lock at all, but in the background there is **refcounting**. At least that was my interpretation. So it may not be obvious for a developer to include write lock here. But.. refcounting can race too :)
```
vmwp!Vml::VmSharableObject::DecrementUserCount+0x59:
00007ff7`88312d5d 488b07          mov     rax,qword ptr [rdi] ds:00000210`a424bfb0=????????????????
```
  - How did I fuzzed it: automation .. essentially can be seen as a by-product while fuzzing at scale. Well.. what I realized fuzzing is, and why automation is an essential part of your fuzzing efforts, not only as automation, will be in the scope of the next post. Meanwhile to sum it up, lucky me :)

  - How to reach to fuzz : 
    + [Hyper-V Cmdlets](https://docs.microsoft.com/en-us/powershell/module/hyper-v/?view=windowsserver2022-ps) yep that is right, Azure attack is not Pwn2Own attack, and for example turn on/off is something that attacker can do
    + though this is always on the edge, about turn off bugs for example check [February 23, 2021 Revision](https://www.microsoft.com/en-us/msrc/bounty-hyper-v)
    
  - POC
    + example how to make Race Conditions better demonstrate for repro
    + second part of poc is turn on+off VM
    
```
.childdbg 1 
g 

.logopen sharablebuggy.txt; 

r @$t1 = 0
bp vmwp!VirtualMachine::InitInterceptHandlers+0x154 "r @$t1 = @rax+60; g"

bp vmwp!Vml::VmSharableObject::DecrementUserCount+0x59 ".if(@$t1==@rdi+10){.echo RACER_1_FREEZED; bd 1 2; be 4; dqs rdi; r rip = vmwp!Vml::VmSharableObject::DecrementUserCount-2; eb rip eb fe}.else{}; g"

bp vmwp!Vml::VmSharableObject::DecrementUserCount-2 ".echo RACER_1_RESUMED___UAF_TRIGGER; r rip = vmwp!Vml::VmSharableObject::DecrementUserCount+0x59; g"

bu vmwp!VirtualMachine::Teardown+0x1d0-5 ".echo RACER_2_TEARDOWN_FREEZED; bd 3; r rip = vmwp!VirtualMachine::Teardown-2; eb rip eb fe; g"

bp vmwp!VirtualMachine::Teardown-2 ".echo RACER_2_TEARDOWN_RESUMED; r rip = vmwp!VirtualMachine::Teardown+0x1d0-5; g"

bp vmwp!VirtualMachine::Teardown+0x1d0 ".echo RACER_2_TEARDOWN_FINISHED___UAF_GO; be 2; g"

g

```
    

### *Few highlights to note :*
> all of them RCE + UAF, to be honest most of my bugs are races due to the nature of my fuzzing, but Hyper-V is not an eve's garden for data format bugs anyway.

> bugs were not at fuzzing obvious target logic (files) path, but at the upper level (work items / packet handling)

> for those bugs using code coverage-based fuzzer can shoot you in your feet at very least. On the other side, as I mentioned above, code coverage can play an essential role if used appropriately (hinting at weak points of fuzzer instead of main logic of fuzzer)

> Hyper-V is hard (?). all mentioned bugs, have some hidden quirk to reach, is not an obvious mistake by developer - quite opposite - code looks solid and well thought over, but you need magic eyes to catch those by analysis as a bug hunter, though fuzzing may change the game

> very similar (cancel or Vnd+TearDown) but different in nature (more fuzzy approach vs more static approach by my understanding) examples you can find by really cool resource [Mobius Band](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Mobius-Band-Explore-Hyper-V-Attack-Interface-Through-Vulnerabilities-Internals.pdf)

> low hanging fruits is a luxury term, it always depends. After retrospective, we may call perhaps all memory corruption bugs low hanging fruits :) what can help you finding yours LHF is persistence, accumulated experience, luck and opportunity (time). 

## Teaser : Research on the Rise

In this post I covered the first bugs after a 2 year long gap I took, meanwhile I did some deep research, lol, on reinforcement learning (RL) which was a very nice refresh, and got some good knowledge that I may or may not use in my future research.  And afterward I have taken, yet again, several months off, to finish my knowledge pursue for RL and mastering of Slavic life (making own fruit booze, planting trees, eating more bananas, constructing some building which should last a year or two before collapses cuz wind rain or so, well trying new stuff :). But a few months ago I got kicked off from my ofsec slumber by mentioned Mobius Band, to remind me that I should repay my debt and do some sharing myself too. There I am again, me + Hyper-V + fresh ideas, which reflects to about 10 Tier-1 bugs I reported recently, including RCEs, Memory reads, and DoSes, new attack surface - but also traditional one. In contrast highlighted bugs were focused on containers part of Hyper-V bounty, Tier-2.

{:refdef: style="text-align: center;"}
![oo(p)s](https://rezer0dai.github.io/assets/images/bounty_oops.png)
{:refdef}

However, about 3 of my recent bugs were marked out of scope, and so the next part of this post will be focused on that. Will be less technical and less brief, as I will try to share my point of view to recent **Hyper-V Bounty** confusions, to prevent the frustration of security researchers, such as myself, from cooling joy by "big" to "bug" bounty assessment.     

As a side note, I got also some ideas for future research and my fuzzing approaches, so stay tuned, I may or may not drop something soon. Meanwhile, those are nice drops, which may inspire you too: 
  - https://github.com/RUB-SysSec/nyx-net
  - https://www.microsoft.com/en-us/research/publication/hyperfuzzer-an-efficient-hybrid-fuzzer-for-virtual-cpus/
  - https://github.com/0vercl0k/wtf
  - https://googleprojectzero.blogspot.com/2021/09/fuzzing-closed-source-javascript.html?m=1
  - https://ieeexplore.ieee.org/document/9152719
  - https://twitter.com/SarahJamieLewis/status/1462190704751374337
  - https://github.com/nautilus-fuzz/nautilus
  - https://www.computer.org/csdl/journal/ts/5555/01/09583875/1xSHTQhhdv2


Btw. In my next blog post, I plan to cover more about what I consider what fuzzing is, especially towards targets like Hyper-V where conventional fuzzing seems not so effective and how do I approach it. 

## SetBacks : See you space Cowboy

As a first step, I will describe my "setbacks" with big bounties i had so far, particularly Microsoft one, as that is the only one I have experience with.

- NetBios: CVE-2017-0161 quite joy to blue-screen host from VM for the first time. Got 0k or 5k I think :) That time I am not even sure I submitted it for money. Damn, that time I didn't care about bounties, just CVE and good feeling was enough, as that was a really cool bug for me!


- SMB2 triggerable: CVE-2020-17096 aaaa man, quite a disappointment, after 2years I am back, and moreover with promising 100k target. Got Post-Auth SMB2 but with unsigned packets! meaning? MitM attack after user auth as easy to tamper with unsigned packets.. got 5k, and dumped this research ahaha right afterward, what a depressing moment, you know I was hoping for 100k and glory :) what a change of attitude from NetBios one right? but in my defense, was complicated to setup fuzzing for SMB2 with that signing, key, handshake, etc, a lot of work I made, ouch .. but I somehow get it, MitM was not something MSFT is looking for. Also that I trigger it through SMB does not necessarily mean it is SMB bug.


- Vid.sys CVE-2017-8664 my first Hyper-V Tier-1 RCE **EVER** !! The price tag that time was 50k, a few months later I think 150. Heart Bleeding! Also, I reported 2 bugs for that component, one found via automation and spend 2 months of debugging (getting hints and proving a theory, was one of the most coolest bug of mine tbh), and for the second one, I made fuzzer and trigger brother bug, but was coalesced to one CVE as one patch. Were it be two bugs if I reported in a different order or wait? Tbh I asked and they said no, their patch will get both regardless of which I reported first. But still 2 bugs vs 1 CVE, bleeding :( but I'm really proud of this one, and fuzzing was cool too! 


- Containers: 2 CVE-??, opsy loose those ones, but one was described at vsmb bonus. In short nice bugs, nice fuzzing, proud feeling, 25k, fair enough. Meh, a few months later the bounty price tag raised 100k for containers bug. Meaning? If I waited, I could have 200 instead of 50, hmmm, again, ouch? :) Actually, I was cool with that, part of the evolution of bounty.


- RFG + CFG bounties for mitigation bypasses. Cool! Was happy I unlocked the achievement of Mitigation Bypass Bounty and 2 times!! Pretty proud of myself up to today actually! But then I got one more CFG bypass, Suppressed Exports, but .. that got slammed with CFG race condition bypasses **out of scope**.. sight :(


- Turn Off Hyper-V vulns, one was for s3video, the second was mentioned as last of three highlighted at this post CVE-2021-28314. considered to be Tier-3 aka 10x lower bounty - until proven exploitability, as in general unsure if exploitable :( Actually, I agree on that one, at least for Tier-2, for Tier-1 seems less challenging to make working exploit-poc, but that I will play with once I got that kind of bug :)


What can be learned from this? I guess first most obvious is that my greed grows exponentially :) Secondly, the bounty program, at least MSFT one, evolves over time. Third, as it may seem sometimes unfair, based on your results can be set new standards which will benefit to others but will not be backported to your past cases (Note that I am attributing to myself here too much, that is imho my normal habit, while actually, I bet it was a coincidence and "unfortunate" timing from my side at least at most mentioned cases), and that is part of the game too.

## Out of Scope : Oo(p)S

Ok, now, in recent months it seems the Out-of-Scope part of Hyper-V bounty got a huge ramp-up. To understand why is that, let's consider a few scenarios : 

  - NetBios bug, RCE on a host from VM
  - RDP bug via enhanced session
  - WSL2 specifics
  - RemoteFX
  - SMB/Ntfs kernel bug - direct(network) or through vSMB(proxy)
  - WDAG
  
Those are all specific edge cases for particular usage. But how much impact does it have for *MSFT core business model* : **AZURE** ? And even if I can trigger from the cloud, does it really mean it is a Hyper-V design problem ? 

On the other side, I agree there should be some gray zone, like not all Windows RCE bugs could escape Hyper-V, and vice versa, not every module communicating through vmbus is Hyper-V code. There are other gray wannabe zones like Admin -> Kernel boundary, kernel modules within Hyper-V sandbox, etc. Actually, for some, there are special bounty programs like [Insider RCE](https://www.microsoft.com/en-us/msrc/bounty-windows-insider-preview) or [WDAG](https://www.microsoft.com/en-us/msrc/bounty-windows-defender-application-guard), and for the others programs may come.  

But as far as I understand for Hyper-V bounty, Microsoft is concerned on quite a minimalistic approach - thus so high bounties, less code less place for mistakes. And what they can essentially serve on the cloud for users that way. That means, no enhanced session, no remote fx, no wsl2. Smb, NetBios, Ntfs, core ALPC, all not a Hyper-V design. Just old plain default modules, default settings. And in that regard, *million dollar question is: what is triggerable in default cloud settings ? What about docker / kubernetes ?*


Tbh I am not sure about the full scope of the attack surface myself, I am feeling a lack of documentation on this. Like what kind of settings can we alter, what an attacker actually can do outside of a VM. But how easy it is to provide security researchers with this kind of playground, I honestly don't know. Therefore best thing we could do, is in case of uncertainty about attack surface, to ask them through the [email](mailto:secure@microsoft.com), maybe some arguments if their explanation is not clear enough or we think they don't see what we see, in general finding common ground of understanding. But meanwhile, in my next blog post, I go on to enumerate the default surface I am aware of.

## outro

As joyful or frustrating it may be, that seems is the game of Bounty Hunter. We first need to understand that the bounty is completely in the hand of the company, if they consider bug to be worth that reward, and that they are not even obligated to do so. I think we have also grown little over ourselves in recent years. I certainly did, and I try to think in a way, that fixing my bug will not fix security itself, but sometimes I have just too big eyes my hopes were too high and my understanding and empathy towards the other side is lacking, so with this, I apologize to MSRC for the times when I do argue too hard.

I understand that there are more options, not just vendors. But on that accord, need to take into consideration that the other options require, as far as I understand, stable exploit and particular attack surface need to be in other party wanted list - basically same as with vendor, just list may differ I guess. However on top of it working on a stable exploit may be more time-consuming than finding another bug, likely more money but comes with a different responsibility / blind eye too. Also important questions like: how much money is enough? are we doing it just for money?

Like it may frustrate us to find a bug and not to be appreciated for it, it is nothing and even outrageous to compare it to the 'frustration' of once living beings we casually put on our dining tables without questions.

Which is, likely, the worst crime in the history of humankind towards, likely, most innocent creatures on the planet. And whatever our excuses for continuing our personal contribution to it are, there is only one thing we really need to know: [that it is completly](https://www.pcrm.org/news/health-nutrition/academy-nutrition-and-dietetics-publishes-stance-vegan-and-vegetarian-diets) [unecesary](https://pubmed.ncbi.nlm.nih.gov/27886704/). 

Moreover in these days, when boosting our immunity and contributing our 5cents to preventing global health pandemic is topmost importance, we easily tend to forget the importance of our competence and keep relying only on others and temporary patches. While patching is important, mitigations are, if done right, stepping up the game.
That being said maybe it is time to revisit the importance of fiber+vitamins(C,D,B12 among others)+minerals
in our diet and extend compassion, esp. towards most vulnerable and exploited ones, in our lifestyles, [now](https://github.com/rezer0dai/bananafzz)


## thanks

As my friend, [Axel](https://twitter.com/0vercl0k), said once we first met at BlueHat (after I found "my" Vid bug ): "man, you can be a millionaire!" well or something between those lines :) And yes, you can be too! Here I selected one of the emails I got from Microsoft - picked one from bugs I described in the post (usually I am not doing this, but just as proof that they do deliver): 

{:refdef: style="text-align: center;"}
![bountyX](https://rezer0dai.github.io/assets/images/bounty_screen.png)
{:refdef}


In recap I would like to express my thanks to [kostya](https://twitter.com/crypt0ad), for his [ultimate public breakthrough research](https://bugs.chromium.org/p/project-zero/issues/detail?id=690&redir=1) which inspired me and paved way for me and others. [Joe](https://twitter.com/JosephBialek), [Nico](https://twitter.com/n_joly), [Axel](https://twitter.com/0vercl0k), [Max](https://twitter.com/Dor3s) and [Marco](https://twitter.com/marcograss) for proof-reading.

Last but not least, Microsoft and MSRC, for patience with me and my arguing .. and for bounties of course.

