import MusiaLogo from '../assets/logo_MusIA.png';
import Listening from './Listening';
import '../styles/Home.css';
import { useEffect, useState } from 'react';

function Home({selectedModel,setIsContent,isListening,setIsListening,isReceiving,setIsReceiving}) {
  const [id, setid] = useState('');
  const [FinishL, setIsFinishL] = useState(false)
  useEffect(() => {
    if (isListening === true && FinishL === false) {
      var constraints = { audio: true }
      var chunks = []
      
      navigator.mediaDevices.getUserMedia(constraints)
        .then(function(stream) {
          const recorder = new MediaRecorder(stream);

          recorder.ondataavailable = event => {
            chunks.push(event.data);
          };

          const sleep = time => new Promise(resolve => setTimeout(resolve, time));

          (async () => {
            if (isListening === true) {
              recorder.start(7000);
              await sleep(8000); // wait for 10 seconds before stopping the recorder
              await recorder.stop();
              setIsFinishL(true);
            }
          })();

          recorder.onstop = async () => {
            var blob = new Blob(chunks, { type: "audio/mp3" });
            var xmlhttp = new XMLHttpRequest();
            var url = " https://0674-49-237-18-104.ngrok-free.app/api/v01/post/audio-blob/?model="+selectedModel;
            xmlhttp.open("POST", url, true);
            xmlhttp.setRequestHeader("Content-type", "audio/mp3");
            xmlhttp.setRequestHeader("ngrok-skip-browser-warning","69420");
            xmlhttp.onreadystatechange = function() {
              if (xmlhttp.readyState === 4 && xmlhttp.status === 200) {
                setid(xmlhttp.responseText.toString());
                
                
                setIsListening(false);
              }
            };
            xmlhttp.send(blob);
          };
        })
        .catch(function(err) {
          setIsReceiving(false);
          setIsListening(false);
          setIsContent(0);
        });
    }

    if (FinishL === true) {
      setIsReceiving(true);
    }
  }, [selectedModel,isListening,FinishL,setIsListening,setIsReceiving,setIsFinishL,id,setIsContent]);
  
  // LISTENING TO THE MICROPHONE
  return isListening || (isReceiving && id !== 0) ? (
    <Listening selectedModel={selectedModel} id={id} setIsContent={setIsContent} isReceiving={isReceiving} setIsReceiving={setIsReceiving} setIsListening={setIsListening}/>
  )  :  (
    <div className="Home">
      <p className='NameButton'>
        Cliquez sur l'icone pour démarrer l'écoute.
      </p>
      <button className="transbutton" alt="Stop Listening" onClick={() => setIsListening(true)}><img src={MusiaLogo} className="App-logo-2" alt="Logo" /></button>
      
      <button className="Button" alt="Change to URL" onClick={() => setIsContent(1)}>Test URL</button>
    </div>
  );
}

export default Home;

