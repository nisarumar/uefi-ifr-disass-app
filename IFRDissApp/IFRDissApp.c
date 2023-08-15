/** @file
  IFRDissApp - Shell Application to Dissassemble HII Database
  Copyright (c) 2023, Umar Nisar (umarnisar@outlook.com)
  Copyright (c) 2007 - 2021, Intel Corporation. All rights reserved.
  All rights reserved. This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#include <Uefi.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/HiiDatabase.h>
#include <Library/HiiLib.h>
#include <Library/ShellLib.h>
#include <Library/PrintLib.h>
#include <Library/DebugLib.h>
#include <stdio.h>
#include <json.h>

typedef struct EFI_FORM_REF_LL
{
	EFI_FORM_ID	formID;
	json_object* jsonObj;
	LIST_ENTRY listEntry;
}EFI_FORM_REF_LL_T;

typedef struct EFI_TIMER_CONTEXT
{
	EFI_EVENT	PeriodicTimer;
	BOOLEAN		CloseTimer;
	BOOLEAN		Refresh;
	BOOLEAN		Pause;
	UINTN		Ticks_1s;

}EFI_TIMER_CONTEXT_T;

typedef struct EFI_STRING_HASH {
	EFI_STRING* StringHash;
	UINTN StringHashMaxSz;
	UINTN StringHashSz;
}EFI_STRING_HASH_T;
/**
  Get String Length

  @param[in] String  Input EFI_STRING for which length to be found.

  @retval  UINTN  Length of String
**/
STATIC inline
UINTN
IFRUCS2StringLen(
	IN   EFI_STRING  String
)
{
	UINTN  Length;
	for (Length = 0; *String != L'\0'; String++, Length++) {
		;
	}
	return Length;
}

static inline
VOID
IFRTimerHandler(
	IN EFI_EVENT Event,
	IN VOID* Context
)
{
	EFI_TIMER_CONTEXT_T* timer = (EFI_TIMER_CONTEXT_T*)Context;
	if (timer->Refresh)
	{
		timer->Ticks_1s = 0;
		Print(L"\n");
		timer->Refresh = FALSE;
	}
	else
	{
		if (!timer->Pause)
		{
			timer->Ticks_1s++;
			Print(L".");
		}
	}
	if (timer->CloseTimer)
	{
		gBS->CloseEvent(Event);
		timer->CloseTimer = FALSE;
	}
}

STATIC inline
EFI_STATUS
AddObjectToLL(
	json_object* objectRef,
	EFI_FORM_ID FormId,
	LIST_ENTRY* ListHead
)
{
	UINTN Status = EFI_SUCCESS;
	EFI_FORM_REF_LL_T* Ptr = NULL;

	Status = gBS->AllocatePool(EfiBootServicesData, sizeof(EFI_FORM_REF_LL_T), &Ptr);

	if (EFI_ERROR(Status))
	{
		DEBUG((EFI_D_WARN, "Error Allocating Space - %r \n", Status));
		return EFI_OUT_OF_RESOURCES;
	}

	Ptr->formID = FormId;
	Ptr->jsonObj = objectRef;

	Status = (ListHead == InsertTailList(ListHead, &Ptr->listEntry)) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;

	return Status;
}

STATIC inline
LIST_ENTRY*
RemoveObjectFromLL(
	LIST_ENTRY* entry
)
{
	EFI_FORM_REF_LL_T* currObj = NULL;
	LIST_ENTRY* NextEntry = NULL;
	currObj = BASE_CR(entry, EFI_FORM_REF_LL_T, listEntry);
	NextEntry = RemoveEntryList(entry);
	gBS->FreePool(currObj);
	return NextEntry;
}

STATIC inline
EFI_STATUS
FreeAllEntries(
	LIST_ENTRY* listHead
)
{
	LIST_ENTRY* currElem = GetNextNode(listHead, listHead);

	while (currElem != listHead)
	{
		currElem = RemoveObjectFromLL(currElem);
	}
}

STATIC inline
json_object*
GetObjectFromLL(
	const LIST_ENTRY* formRefsHead,
	const UINTN formID
)
{
	EFI_FORM_REF_LL_T* currObj = NULL;
	json_object* parentObj = NULL;

	for (LIST_ENTRY* currElem = GetNextNode(formRefsHead, formRefsHead);
		formRefsHead != currElem && parentObj == NULL;
		currElem = GetNextNode(formRefsHead, currElem))
	{
		currObj = BASE_CR(currElem, EFI_FORM_REF_LL_T, listEntry);
		if (currObj->formID == formID)
		{
			parentObj = currObj->jsonObj;
			RemoveObjectFromLL(currElem);
		}
	}

	return parentObj;
}

RETURN_STATUS
EFIAPI
ConverToAscii(
	IN      CHAR16* Source,
	OUT     CHAR8* Destination,
	IN      UINTN         DestMax
)
{
	UINTN  SourceLen;

	ASSERT(Destination != NULL);
	ASSERT(Source != NULL);
	ASSERT(DestMax != 0);

	SourceLen = IFRUCS2StringLen(Source);

	ASSERT(DestMax > SourceLen);

	while (*Source != '\0') {
		if ((*Source) > 0x7E)
		{
			*(Destination++) = (CHAR8)'?';
			Source++;
		}
		else
			*(Destination++) = (CHAR8) * (Source++);
	}

	*Destination = '\0';

	return RETURN_SUCCESS;
}

EFI_STATUS
GetStrings(
	IN EFI_HII_PACKAGE_LIST_HEADER* PkgListEntry,
	IN EFI_STRING_HASH_T* strHash
)
{
	EFI_STATUS Status = EFI_SUCCESS;

	strHash->StringHashSz = 0;

	UINTN size = PkgListEntry->PackageLength - sizeof(EFI_HII_PACKAGE_LIST_HEADER);

	for (EFI_HII_PACKAGE_HEADER* packageEntry = (EFI_HII_PACKAGE_HEADER*)(PkgListEntry + 1);
		(UINTN)packageEntry < (UINTN)(PkgListEntry + 1) + size;
		packageEntry = (EFI_HII_PACKAGE_HEADER*)((UINT8*)packageEntry + packageEntry->Length))
	{
		if (packageEntry->Type == EFI_HII_PACKAGE_STRINGS)
		{
			EFI_HII_STRING_PACKAGE_HDR* StringHDR = (EFI_HII_STRING_PACKAGE_HDR*)packageEntry;

			if (0 == AsciiStrCmp(StringHDR->Language, "en-US"))
			{
				if (strHash->StringHashSz < strHash->StringHashMaxSz)
				{
					strHash->StringHashSz++;
				}
				else
				{
					Status = EFI_BUFFER_TOO_SMALL;
				}
				EFI_HII_STRING_BLOCK* block = (EFI_HII_STRING_BLOCK*)(((UINT8*)StringHDR) + StringHDR->StringInfoOffset);

				while (!EFI_ERROR(Status) && block->BlockType == EFI_HII_SIBT_STRING_UCS2)
				{
					EFI_HII_SIBT_STRING_UCS2_BLOCK* currBlock = (EFI_HII_SIBT_STRING_UCS2_BLOCK*)block;

					if (strHash->StringHashSz < strHash->StringHashMaxSz)
					{
						strHash->StringHash[strHash->StringHashSz++] = (EFI_STRING)currBlock->StringText;
					}
					else
					{
						Status = EFI_BUFFER_TOO_SMALL;
					}
					block = (EFI_HII_STRING_BLOCK*)(((UINTN)currBlock->StringText) + IFRUCS2StringLen(currBlock->StringText) * 2 + 2);
				}
			}
		}

	}

	return Status;

}

EFI_STATUS
GetJsonStr(
	IN UINTN StringID,
	IN EFI_STRING_HASH_T* StrHash,
	IN CHAR8* AsciiStr,
	IN UINTN AsciiSize
)
{
	if (StringID > StrHash->StringHashSz)
		return EFI_BUFFER_TOO_SMALL;
	if (StringID == 0)
	{
		AsciiStr = NULL;
		return EFI_SUCCESS;
	}
	return  ConverToAscii(StrHash->StringHash[StringID], AsciiStr, AsciiSize);
}

EFI_STATUS
ParseFormSet(
	IN EFI_IFR_OP_HEADER* OpHeader,
	IN SHELL_FILE_HANDLE FileHandle,
	IN EFI_STRING_HASH_T* StrHash,
	OUT json_object* root
)
{
	UINTN Scope = 0;
	EFI_STATUS status = 0;
	CHAR8 jsonStr[1024];
	CHAR8 entry[20];
	json_object* ParentsArr[20] = { NULL };
	ParentsArr[0] = root;
	UINTN optionCount = 0;
	CHAR8* QuestionType = NULL;

	LIST_ENTRY FormRefListHead;
	InitializeListHead(&FormRefListHead);

	do {
		if (OpHeader->Scope)
		{
			Scope++;
			ParentsArr[Scope] = ParentsArr[Scope - 1];
		}
		switch (OpHeader->OpCode)
		{
		case EFI_IFR_FORM_SET_OP:
			ParentsArr[Scope] = json_object_new_object();
			EFI_IFR_FORM_SET* FormSet = (EFI_IFR_FORM_SET*)OpHeader;
			sprintf(&entry[0], "%s", "FormSet");
			json_object_object_add(ParentsArr[Scope - 1], &entry[0], ParentsArr[Scope]);
			status = GetJsonStr(FormSet->FormSetTitle, StrHash, jsonStr, sizeof(jsonStr));
			if (!EFI_ERROR(status))
				json_object_object_add(ParentsArr[Scope], "FormSetTitle", json_object_new_string(jsonStr));
			break;
		case EFI_IFR_GUID_OP:
			EFI_IFR_GUID* Guid_Form = (EFI_IFR_GUID*)OpHeader;
			CHAR16 GUIDStr[37];
			UnicodeSPrint(&GUIDStr[0], sizeof(GUIDStr), L"%g\n", Guid_Form->Guid);
			status = UnicodeStrToAsciiStrS(&GUIDStr[0], jsonStr, sizeof(jsonStr));
			if (!EFI_ERROR(status))
				json_object_object_add(ParentsArr[Scope], "Guid", json_object_new_string(jsonStr));
			break;
		case EFI_IFR_DEFAULTSTORE_OP:
			//sprintf(&entry[0], "%s_%d\n", "Entry", count);
			//json_object_object_add(ParentsArr[Scope], &entry[0], json_object_new_string("EFI_IFR_DEFAULTSTORE_OP"));
			break;
		case EFI_IFR_VARSTORE_OP:
			//sprintf(&entry[0], "%s_%d\n", "Entry", count);
			//json_object_object_add(ParentsArr[Scope], &entry[0], json_object_new_string("EFI_IFR_VARSTORE_OP"));
			break;
		case EFI_IFR_VARSTORE_EFI_OP:
			//sprintf(&entry[0], "%s_%d\n", "Entry", count);
			//json_object_object_add(ParentsArr[Scope], &entry[0], json_object_new_string("EFI_IFR_VARSTORE_EFI_OP"));
			break;
		case EFI_IFR_FORM_OP:
			//Print(L"EFI_IFR_FORM_OP\n");
			ParentsArr[Scope] = json_object_new_object();
			EFI_IFR_FORM* IFRForm = (EFI_IFR_FORM*)OpHeader;
			sprintf(&entry[0], "%s_%d", "Form", IFRForm->FormId);
			json_object* temp = GetObjectFromLL(&FormRefListHead, IFRForm->FormId);
			json_object_object_add(ParentsArr[Scope - 1], &entry[0], ParentsArr[Scope]);
			status = GetJsonStr(IFRForm->FormTitle, StrHash, jsonStr, sizeof(jsonStr));
			if (!EFI_ERROR(status))
			{
				json_object_object_add(ParentsArr[Scope], "FormTitle", json_object_new_string(jsonStr));
				if (temp != NULL)
				{
					json_object_set_string(temp, jsonStr);
				}
			}
			break;
		case EFI_IFR_SUPPRESS_IF_OP:
		case EFI_IFR_GRAY_OUT_IF_OP:
			break;
		case EFI_IFR_SUBTITLE_OP:
			//sprintf(&entry[0], "%s_%d\n", "Entry", count);
			//json_object_object_add(ParentsArr[Scope], &entry[0], json_object_new_string("EFI_IFR_SUBTITLE_OP"));
			break;
		case EFI_IFR_TEXT_OP:
			//sprintf(&entry[0], "%s_%d\n", "Entry", count);
			//json_object_object_add(ParentsArr[Scope], &entry[0], json_object_new_string("EFI_IFR_TEXT_OP"));
			break;
		case EFI_IFR_REF_OP:
			EFI_IFR_REF* IFRRef = (EFI_IFR_REF*)OpHeader;
			sprintf(&entry[0], "%s_%d", "FormRef", IFRRef->FormId);
			json_object* tempRef = json_object_new_string("");
			json_object_object_add(ParentsArr[Scope], &entry[0], tempRef);
			AddObjectToLL(tempRef, IFRRef->FormId, &FormRefListHead);
			break;
		case EFI_IFR_END_OP:
			Scope--;
			break;

		case EFI_IFR_ONE_OF_OP:
			if (!QuestionType)
			{
				QuestionType = "OneOf";
			}
		case EFI_IFR_CHECKBOX_OP:
			if (!QuestionType)
			{
				QuestionType = "CheckBox";
			}
		case EFI_IFR_NUMERIC_OP:
			if (!QuestionType)
			{
				QuestionType = "Numeric";
			}
		case EFI_IFR_STRING_OP:
			if (!QuestionType)
			{
				QuestionType = "String";
			}
			optionCount = 0;
			EFI_IFR_ONE_OF* IFROneOf = (EFI_IFR_ONE_OF*)OpHeader;

			if (OpHeader->Scope)
			{
				ParentsArr[Scope] = json_object_new_object();
				sprintf(&entry[0], "%s_%d", QuestionType, IFROneOf->Question.QuestionId);
				json_object_object_add(ParentsArr[Scope - 1], &entry[0], ParentsArr[Scope]);
			}
			status = GetJsonStr(IFROneOf->Question.Header.Prompt, StrHash, jsonStr, sizeof(jsonStr));
			if (!EFI_ERROR(status))
				json_object_object_add(ParentsArr[Scope], "Prompt", json_object_new_string(jsonStr));

			status = GetJsonStr(IFROneOf->Question.Header.Help, StrHash, jsonStr, sizeof(jsonStr));

			if (!EFI_ERROR(status))
			{
				json_object_object_add(ParentsArr[Scope], "Help", json_object_new_string(jsonStr));
			}

			json_object* varObj = json_object_new_object();
			json_object_object_add(varObj, "varOffset", json_object_new_int(IFROneOf->Question.VarStoreInfo.VarOffset));
			json_object_object_add(varObj, "varStoreIdx", json_object_new_int(IFROneOf->Question.VarStoreId));
			json_object_object_add(ParentsArr[Scope], "VarInfo", varObj);
			QuestionType = NULL;
			break;
		case EFI_IFR_ONE_OF_OPTION_OP:
			EFI_IFR_ONE_OF_OPTION* IFROneOfOp = (EFI_IFR_ONE_OF_OPTION*)OpHeader;
			status = GetJsonStr(IFROneOfOp->Option, StrHash, jsonStr, sizeof(jsonStr));
			sprintf(&entry[0], "%s_%d", "Option", ++optionCount);
			ASSERT(ParentsArr[Scope] != NULL);
			if (!EFI_ERROR(status))
				json_object_object_add(ParentsArr[Scope], &entry[0], json_object_new_string(jsonStr));
			break;
		default:
			break;
		}
		OpHeader = (EFI_IFR_OP_HEADER*)((UINTN)OpHeader + OpHeader->Length);
	} while (Scope != 0);

	FreeAllEntries(&FormRefListHead);
	return EFI_SUCCESS;
}

/**
  Entry Point of the Application

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
main(
	IN EFI_HANDLE        ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
)
{
	EFI_STATUS  Status;
	EFI_HII_DATABASE_PROTOCOL* HiiDBPr;
	UINTN PkgListSz = 0;
	EFI_HII_PACKAGE_LIST_HEADER* HiiPkgLsts = NULL;
	EFI_HII_PACKAGE_LIST_HEADER* HiiPkgLstsEntry;
	EFI_HII_PACKAGE_HEADER* packageEntry;
	EFI_STRING_HASH_T* StringHashTableData;
	VOID* timerPtr;
	Status = gBS->AllocatePool(EfiBootServicesData, sizeof(EFI_TIMER_CONTEXT_T), &timerPtr);

	if (EFI_ERROR(Status))
	{
		DEBUG((EFI_D_WARN, "Cannot allocate space - %r \n", Status));
		return EFI_OUT_OF_RESOURCES;
	}
	volatile EFI_TIMER_CONTEXT_T* timer = (EFI_TIMER_CONTEXT_T*)timerPtr;

	Status = gBS->CreateEvent(
		EVT_TIMER | EVT_NOTIFY_SIGNAL,  // Type
		TPL_NOTIFY,                     // NotifyTpl
		IFRTimerHandler,                   // NotifyFunction
		timerPtr,                         // NotifyContext
		&((EFI_TIMER_CONTEXT_T*)timerPtr)->PeriodicTimer          // Event
	);

	timer->CloseTimer = FALSE;
	timer->Ticks_1s = 0;
	timer->Refresh = FALSE;
	timer->Pause = TRUE;

	gBS->SetTimer(
		((EFI_TIMER_CONTEXT_T*)timerPtr)->PeriodicTimer,
		TimerPeriodic,
		EFI_TIMER_PERIOD_MILLISECONDS(1000)
	);

	if (EFI_ERROR(Status))
	{
		DEBUG((EFI_D_WARN, "Cannot create event - %r \n", Status));
		return EFI_DEVICE_ERROR;
	}

	Status = gBS->AllocatePool(EfiBootServicesData, sizeof(EFI_STRING_HASH_T), &StringHashTableData);

	if (EFI_ERROR(Status))
	{
		DEBUG((EFI_D_WARN, "Cannot allocate space - %r \n", Status));
		return EFI_OUT_OF_RESOURCES;
	}

	StringHashTableData->StringHashSz = 0;
	StringHashTableData->StringHashMaxSz = 0x1B58;
	VOID* ptr = NULL;
	Status = gBS->AllocatePool(EfiBootServicesData, sizeof(EFI_STRING) * StringHashTableData->StringHashMaxSz, &ptr);
	StringHashTableData->StringHash = (EFI_STRING*)ptr;

	if (EFI_ERROR(Status))
	{
		DEBUG((EFI_D_WARN, "Error Allocating Space - %r \n", Status));
		return EFI_OUT_OF_RESOURCES;
	}

	Status = gBS->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, &HiiDBPr);
	if (EFI_ERROR(Status))
	{
		DEBUG((EFI_D_WARN, "Error Locating Hii DB Protocol - %r \n", Status));
		return EFI_DEVICE_ERROR;
	}

	Status = HiiDBPr->ExportPackageLists(
		HiiDBPr,
		NULL,
		&PkgListSz,
		HiiPkgLsts);

	if (EFI_BUFFER_TOO_SMALL != Status)
	{
		DEBUG((EFI_D_ERROR, "Error in determining Pkg List Size %r\n", Status));
		return EFI_PROTOCOL_ERROR;
	}

	Status = gBS->AllocatePool(EfiBootServicesData, PkgListSz, &HiiPkgLsts);

	if (EFI_ERROR(Status))
	{
		DEBUG((EFI_D_ERROR, "Error Allocating Space  %r\n", Status));
		return EFI_OUT_OF_RESOURCES;
	}

	Status = HiiDBPr->ExportPackageLists(
		HiiDBPr,
		NULL,
		&PkgListSz,
		HiiPkgLsts);

	if (EFI_ERROR(Status))
	{
		DEBUG((EFI_D_ERROR, "Error Exporting Pkg Lists %r\n", Status));
		gBS->FreePool(HiiPkgLsts);
		return EFI_PROTOCOL_ERROR;
	}


	for (HiiPkgLstsEntry = HiiPkgLsts;
		(UINTN)HiiPkgLstsEntry < ((UINTN)HiiPkgLsts) + PkgListSz;
		HiiPkgLstsEntry = (EFI_HII_PACKAGE_LIST_HEADER*)((UINTN)HiiPkgLstsEntry + HiiPkgLstsEntry->PackageLength))
	{
		SHELL_FILE_HANDLE FileHandle;
		UINTN size = HiiPkgLstsEntry->PackageLength - sizeof(*HiiPkgLstsEntry);
		CHAR16 FileName[64];
		CHAR8 JsonFileName[64];

		UnicodeSPrint(FileName, sizeof(FileName), L"Package%g.hpk", &HiiPkgLstsEntry->PackageListGuid);
		Status = ShellOpenFileByName(FileName, &FileHandle, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);

		if (EFI_ERROR(Status))
		{
			DEBUG((EFI_D_ERROR, "Error Opening File - %r\n", Status));
			return EFI_OUT_OF_RESOURCES;
		}

		Status = ShellWriteFile(FileHandle, &size, (UINTN*)(HiiPkgLstsEntry + 1));
		if (EFI_ERROR(Status))
		{
			DEBUG((EFI_D_ERROR, "Error Writing File - %r\n", Status));
		}

		ShellCloseFile(&FileHandle);

		GetStrings(HiiPkgLstsEntry, StringHashTableData);

		packageEntry = (EFI_HII_PACKAGE_HEADER*)(HiiPkgLstsEntry + 1);

		while (size > 0)
		{
			if (packageEntry->Length > size)
			{
				return EFI_VOLUME_CORRUPTED;
			}

			if (packageEntry->Type == EFI_HII_PACKAGE_FORMS)
			{
				EFI_IFR_OP_HEADER* OpHeader = (EFI_IFR_OP_HEADER*)(packageEntry + 1);
				json_object* root = json_object_new_object();
				if (!root)
					return 1;

				timer->Pause = FALSE;
				timer->Refresh = TRUE;
				Print(L"Parsing now\n");
				while (timer->Refresh == TRUE);
				ParseFormSet(
					OpHeader,
					&FileHandle,
					StringHashTableData,
					root);

				Print(L"\nParsing took %d secs\n", timer->Ticks_1s);
				UnicodeSPrint(FileName, sizeof(FileName), L"Package%g.json", &HiiPkgLstsEntry->PackageListGuid);
				Status = UnicodeStrToAsciiStrS(&FileName[0], &JsonFileName[0], sizeof(JsonFileName));

				if (EFI_ERROR(Status))
				{
					DEBUG((EFI_D_ERROR, "Error in filename - %r\n", Status));
				}
				else
				{
					timer->Refresh = TRUE;
					Print(L"Saving results..\n");
					while (timer->Refresh == TRUE);
					if (json_object_to_file(JsonFileName, root))
					{
						DEBUG((EFI_D_ERROR, "Jsonc - Error Saving File - \n"));
					}
					else
					{
						Print(L"Saving Json file took %d secs\n", timer->Ticks_1s);
					}
				}

				timer->Refresh = TRUE;
				Print(L"Freeing Resources..\n");
				while (timer->Refresh == TRUE);
				json_object_put(root);
				Print(L"Freeing resources took %d secs\n", timer->Ticks_1s);
				timer->Pause = TRUE;
			}

			size -= packageEntry->Length;

			if (size == 0 && packageEntry->Type != EFI_HII_PACKAGE_END)
			{
				return EFI_VOLUME_CORRUPTED;
			}

			packageEntry = (EFI_HII_PACKAGE_HEADER*)((UINT8*)packageEntry + packageEntry->Length);
		}

	}

	timer->CloseTimer = TRUE;
	while (timer->CloseTimer);
	gBS->FreePool(timerPtr);
	gBS->FreePool(HiiPkgLsts);
	return EFI_SUCCESS;
}
