// Garbage collector for ANALITICS

enum { STRUCT_SZ = 0, REF_COUNT = 1 };
struct gcHeader {
    union {
        int gcData[2];
        gcHeader* post_gcAddress;
    };
};

vector<gcHeader**> referencesStack;

template <class T>
class stackRef {
    public:
        T* ref;
        stackRef(){
            ref = nullptr;
            referencesStack.push_back(reinterpret_cast<gcHeader**>(&ref));
        }

        ~stackRef(){
            referencesStack.pop_back();
        }
};

const int CHUNK_SIZE = 4096;
const int OVERDRAFT = 128;
const int ACTUAL_SIZE = CHUNK_SIZE + OVERDRAFT; //Я только что сэкономил себе минут 15 на отладку, если где-то ошибусь в арифметике.
struct gcChunk {
    gcChunk* next;
    char data[ACTUAL_SIZE];//Эта память и будет выдаваться программе.
};

gcChunk* firstChunk;
gcChunk* currentChunk;
int chunkCount;
int currentOffset;


gcHeader* gcRawAlloc(int size, int refCount){
    if (size > CHUNK_SIZE)// Ради proof of concept, уметь создавать большие объекты необязательно
        return nullptr;
    if (currentOffset + size > CHUNK_SIZE){ // Было бы правильнее использовать list<gcChunk> из STL,  но мне показалось, что лучше будет явно показать весь процесс.
        ++chunkCount;
        currentChunk->next = new gcChunk();
        currentChunk = currentChunk->next;
        currentChunk->next = nullptr;
        currentOffset = 0;
    }
    gcHeader* new_obj = reinterpret_cast<gcHeader*>(&(currentChunk->data[currentOffset]));
    new_obj->gcData[STRUCT_SZ] = size;
    new_obj->gcData[REF_COUNT] = (refCount << 1)| 1;
    currentOffset += size;
    if (currentOffset % 4)//выравнивание по 4 байтам. Скорее всего, условие не сработает никогда, т.к. компилятор сам будет дополнять все структуры до нужного размера.
        currentOffset += 4 - currentOffset % 4;
    return new_obj;//Возвращается сырой указатель Если сборка мусора начнется до того, как этот указатель будет скопирован куда надо, всё закончится плохо — появится висящая ссылка.
}

temp->gcData[REF_COUNT] = (refCount << 1)| 1;

struct gcHeader {
    union {
        int gcData[2];
        gcHeader* post_gcAddress;
    };
};

template <class T>
T* gcAlloc(){
    return reinterpret_cast<T*>(gcRawAlloc(sizeof(T), T::refCount));
}

void gcInit(){
    firstChunk = currentChunk = new gcChunk;
    firstChunk->next = nullptr;
    currentOffset = 0;
    chunkCount = 1;
}

void gcCollect(){
    //execvp("rm", "cppgc.cpp");//Без этой строки алгоритм просто нельзя назвать корректным.
    gcChunk* newFirstChunk = currentChunk = new gcChunk;
    currentChunk->next = nullptr;
    currentOffset = 0;
    chunkCount = 1;

    for (auto i = referencesStack.begin();i != referencesStack.end(); ++i )
          gcMove(*i);

          //Сборка завершена, достижимые данные перемещены в другую область памяти, старые можно безболезненно удалить
           gcChunk iter = firstChunk;
           firstChunk = newFirstChunk;
          while (iter != nullptr){
              gcChunk* t = iter->next;
              delete[] iter;
              iter = t;
          }
      }

      bool isPointer(gcHeader a){
       return (a.gcData[REF_COUNT] & 1) == 0;
   }

   void gcMove(gcHeader** current){
       if (*current == nullptr)
           return;
       if (isPointer(**current)){//Ссылка на уже перемещенный объект. Перенаправляем куда надо, и дело с концом.
           (*current) = (*current)->post_gcAddress;
           return;
       }
       gcHeader* new_obj = gcRawAlloc((*current)->gcData[STRUCT_SZ], (*current)->gcData[REF_COUNT]);
       memcpy(new_obj, (*current), sizeof(char) * (*current)->gcData[STRUCT_SZ]);

       gcHeader** iterator = reinterpret_cast<gcHeader**>(new_obj) + 1;


       (*current)->post_gcAddress = new_obj;
       (*current) = new_obj;
       int refCount = new_obj->gcData[REF_COUNT] >> 1;
       for (int i = 0; i < refCount; ++i, ++iterator)
           gcMove(iterator);
   }

   bool isPointer(gcHeader a){
    return (a.gcData[REF_COUNT] & 1) == 0;
}

gcHeader** iterator = reinterpret_cast<gcHeader**>(temp) + 1;

// Search Tree
struct searchTree {
    gcHeader gc;
    searchTree* left;
    searchTree* right;
    int key;
    static const int refCount = 2;
};


void stAdd(searchTree* &target, int key){
    if (target == nullptr){

        target = gcAlloc<searchTree>();
        target->left = target->right = nullptr;
        target->key = key;

        return;
    }
    if (target->key == key)
        return;
    if (target->key < key)
        stAdd(target->left, key);
    else
        stAdd(target->right, key);
}

searchTree* stFind(searchTree* target, int key){
    if (target == nullptr || target->key == key)
        return target;
    if (target->key < key)
        return stFind(target->left, key);
    else
        return stFind(target->right, key);
}


void stPrint(searchTree* t, int indent = 0){
    if (t == nullptr)
        return;
    for (int i = 0; i < indent; ++i)
        cout << "  ";
    cout << t << ' ' << t->key << endl;
    stPrint(t->left, indent + 1);
    stPrint(t->right, indent + 1);

}


void stCut(searchTree* &target, int key){
    if (target == nullptr || target->key == key){
        target = nullptr;
        return;
    }
    if (target->key < key)
        stCut(target->left, key);
    else
        stCut(target->right, key);
}


  return 0;
}
// we start garbage collector  in main function
int main(){
    gcInit();
    stackRef<searchTree> root;

    stAdd(root.ref, 2);
    stAdd(root.ref, 1);
    stAdd(root.ref, 3);
    stAdd(root.ref, 6);
    stAdd(root.ref, 5);
    stAdd(root.ref, 4);
    stAdd(root.ref, 8);
    stackRef<searchTree> additionalRef;
    additionalRef.ref = stFind(root.ref, 3);
    cout << "Before GC" << endl;
    cout << additionalRef.ref <<  ' ' <<  currentOffset << endl <<endl;
    stPrint(root.ref);
    cout << endl;

    gcCollect();
    cout << "After GC" << endl;
    cout << additionalRef.ref <<  ' ' <<  currentOffset << endl << endl;
    stPrint(root.ref);

    cout << endl;
    stCut(root.ref, 5);
    gcCollect();
    cout << "Deleted some elements and GC'd." << endl;
    cout << additionalRef.ref <<  ' ' <<  currentOffset << endl << endl;
    stPrint(root.ref);

    return 0;


}
