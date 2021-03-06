import frida
import sys

def main(target):
    session = frida.attach(target)
    script = session.create_script("""
        Process.enumerateModules({
            onMatch: function(module){
                console.log('----------------'+module.name+'----------------');
                Module.enumerateImports(module.name,{
                    onMatch: function(imports){
                        console.log(imports.name);
                    },
                    onComplete: function(){
                })},
            onComplete: function(){}
            })
        """)

    script.load()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[!] Usage: %s <process>" %sys.argv[0])
        sys.exit[1]
    else:
        target=int(sys.argv[1])

    main(target)
