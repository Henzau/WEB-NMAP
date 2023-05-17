import MusiaLogotransparent from '../assets/logo_trans.png'
import '../styles/Content.css';

import { useState, useEffect } from 'react'
import Prediction from './Prediction';

function Listening({selectedModel,id,setIsContent,isReceiving,setIsReceiving,setIsListening}) {
  
  const [data, setdata] = useState({});
  const [isDisplay, setIsDisplay] = useState(false);

 
  useEffect(() => {
    if (isReceiving && !isDisplay && id.length > 1) { // check if id is not undefined or null
      
      fetch(`https://0674-49-237-18-104.ngrok-free.app/api/v01/get/res/?id=`+id+"&model="+selectedModel, {
        method: "get",
        headers: new Headers({
          "ngrok-skip-browser-warning": "69420",
        }),
      })
      .then(response => {
        return response.json(); // <<- Return the JSON Object
      })
      .then(result => {
        if (result[1] === -1) {
          alert("La musique n'a pas été reconnue, essayons par URL");
          setIsReceiving(false);
          setIsListening(false);
          setIsContent(1);
        } else {
          setdata(result);
          setIsDisplay(true);
        }
      })
      .catch(error => { 
        console.error(error);
        const errorMessage = 'Something went wrong';
        console.log(errorMessage);
        setIsListening(0);
        setIsReceiving(0);
        setIsContent(0);
      });
    }
  }, [selectedModel,isReceiving, isDisplay, id, setIsContent, setIsListening, setIsReceiving]);
  
  
  return isReceiving ? (
    <Prediction selectedModel={selectedModel} isDisplay={isDisplay} setIsDisplay={setIsDisplay} data={data} />
  )  :  (
    <div className="ContentListening">
        <button className="transbutton" alt="Listening" ><img src={MusiaLogotransparent} className="App-logo" alt="Logo" /></button>
        <p>
          L'application est en écoute, veuillez patienter.
        </p>
    </div>
  );
} 

export default Listening;
